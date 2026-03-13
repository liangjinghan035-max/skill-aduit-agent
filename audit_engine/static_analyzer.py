"""
Phase 1: 增强型静态分析器
- Python AST 深度扫描（支持数据流追踪）
- JS/TS 正则模式匹配（可扩展为 tree-sitter）
- 混淆检测
- 依赖分析
"""

import ast
import os
import re
import json
import yaml
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from configs.audit_config import (
    PYTHON_DANGER_RULES, JS_DANGER_RULES,
    OBFUSCATION_PATTERNS, KNOWN_MALICIOUS_PACKAGES,
)
# Import network rules and shell rules if available
try:
    from configs.audit_config import PYTHON_NETWORK_RULES
except ImportError:
    PYTHON_NETWORK_RULES = {}
try:
    from configs.audit_config import SHELL_DANGER_RULES
except ImportError:
    SHELL_DANGER_RULES = {}


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"


@dataclass
class Finding:
    """单个审计发现"""
    file: str
    line: int
    severity: str
    category: str           # e.g., "code_execution", "file_ops", "network", "obfuscation"
    rule_id: str             # e.g., "PY-EXEC-001"
    title: str
    description: str
    code_context: str        # 找到问题的代码上下文（前后各5行）
    data_flow: Optional[str] = None   # 数据流路径（如果能追踪到）
    is_user_input_tainted: bool = False  # 是否涉及用户输入
    confidence: float = 0.8  # 静态分析的置信度

    def to_dict(self):
        return asdict(self)


@dataclass
class StaticAnalysisResult:
    """静态分析的完整结果"""
    file: str
    language: str
    findings: list = field(default_factory=list)
    obfuscation_score: float = 0.0
    obfuscation_details: list = field(default_factory=list)
    dependency_issues: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [f if isinstance(f, dict) else f for f in self.findings]
        return d


# ============================================================
# Python AST 深度扫描
# ============================================================

class EnhancedPythonVisitor(ast.NodeVisitor):
    """
    增强的 Python AST 访问器：
    1. 追踪变量赋值链（简化版数据流）
    2. 检测用户输入是否流入危险函数
    3. 识别异常的代码模式
    """

    # 常见的用户输入源
    USER_INPUT_SOURCES = {
        "input", "argv", "environ", "stdin",
        "request", "form", "args", "params", "query",
    }

    def __init__(self, filepath: str, lines: list[str]):
        self.filepath = filepath
        self.lines = lines
        self.findings: list[Finding] = []
        self.obfuscation_score = 0.0
        self.obfuscation_details = []

        # 简化的数据流追踪：变量名 → 是否可能受用户输入污染
        self.tainted_vars: set[str] = set()
        # 追踪 import 的模块
        self.imported_modules: dict[str, str] = {}  # alias → module_name
        # 追踪函数定义中的参数（都视为潜在用户输入）
        self.func_params: set[str] = set()

    def _extract_context(self, lineno: int, window: int = 5) -> str:
        start = max(0, lineno - 1 - window)
        end = min(len(self.lines), lineno + window)
        context_lines = []
        for i in range(start, end):
            marker = ">>> " if i == lineno - 1 else "    "
            context_lines.append(f"{marker}{i + 1:4d} | {self.lines[i].rstrip()}")
        return "\n".join(context_lines)

    def _is_tainted(self, node) -> bool:
        """检查节点是否可能受用户输入污染"""
        if isinstance(node, ast.Name):
            return (node.id in self.tainted_vars or
                    node.id in self.func_params or
                    node.id in self.USER_INPUT_SOURCES)
        if isinstance(node, ast.Call):
            # input(), sys.argv, os.environ.get() 等
            if isinstance(node.func, ast.Name) and node.func.id in self.USER_INPUT_SOURCES:
                return True
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in {"get", "read", "readline", "recv"}:
                    return True
        if isinstance(node, ast.Subscript):
            # something[x] - 如果 something 是 tainted，结果也是
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                return True
        if isinstance(node, ast.JoinedStr):  # f-string
            for val in node.values:
                if isinstance(val, ast.FormattedValue) and self._is_tainted(val.value):
                    return True
        return False

    def _get_call_name(self, node) -> Optional[str]:
        """提取函数调用的全名"""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            if base:
                return f"{base}.{node.attr}"
        return None

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imported_modules[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                self.imported_modules[name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # 函数参数视为潜在用户输入
        old_params = self.func_params.copy()
        for arg in node.args.args:
            self.func_params.add(arg.arg)
        self.generic_visit(node)
        self.func_params = old_params

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        """追踪赋值 - 传播污染标记"""
        is_rhs_tainted = self._is_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name) and is_rhs_tainted:
                self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        call_name = self._get_call_name(node.func)
        if not call_name:
            self.generic_visit(node)
            return

        # 检查是否有参数被用户输入污染
        has_tainted_arg = any(self._is_tainted(arg) for arg in node.args)
        has_tainted_kwarg = any(
            self._is_tainted(kw.value) for kw in node.keywords
        )
        is_tainted = has_tainted_arg or has_tainted_kwarg

        # 检查参数是否全部为硬编码常量
        all_args_constant = self._all_args_constant(node)

        lineno = getattr(node, "lineno", 0)

        # 检查所有规则集（危险函数 + 网络规则）
        all_rule_sets = [
            ("danger", PYTHON_DANGER_RULES),
            ("network", PYTHON_NETWORK_RULES),
        ]

        for rule_source, rule_set in all_rule_sets:
            for severity_name, rules in rule_set.items():
                func_base = call_name.split(".")[-1]
                module_base = call_name.split(".")[0] if "." in call_name else None

                matched = False
                if func_base in rules.get("functions", set()):
                    if module_base and rules.get("modules"):
                        real_module = self.imported_modules.get(module_base, module_base)
                        if real_module.split(".")[0] in rules["modules"]:
                            matched = True
                    elif not rules.get("modules"):
                        matched = True
                    elif not module_base:
                        if func_base in rules.get("functions", set()):
                            matched = True

                # 也通过正则模式匹配（用于更复杂的模式）
                if not matched:
                    line_text = self.lines[lineno - 1] if lineno > 0 and lineno <= len(self.lines) else ""
                    for pat in rules.get("patterns", []):
                        if re.search(pat, line_text):
                            matched = True
                            break

                if matched:
                    actual_severity = severity_name

                    # === 核心改进：减少误报 ===
                    # 细化分析：对常见的合法模式降低严重度
                    
                    # 1. subprocess 相关：检查 shell=True 和参数类型
                    if func_base in ("run", "call", "check_output", "check_call", "Popen"):
                        shell_true = self._has_kwarg_value(node, "shell", True)
                        first_arg_is_list = (
                            node.args and isinstance(node.args[0], ast.List)
                        )
                        first_arg_list_starts_with_const = (
                            first_arg_is_list and
                            node.args[0].elts and
                            isinstance(node.args[0].elts[0], ast.Constant)
                        )
                        # 区分：命令本身是否受污染 vs 只是辅助参数（如 cwd）受污染
                        cmd_is_tainted = (
                            node.args and self._is_tainted(node.args[0])
                        )
                        
                        if shell_true:
                            if cmd_is_tainted:
                                actual_severity = "critical"
                            else:
                                actual_severity = "high"
                        elif first_arg_list_starts_with_const and not cmd_is_tainted:
                            # 命令是硬编码列表 → 非常安全
                            actual_severity = "info"
                        elif first_arg_is_list and not cmd_is_tainted:
                            actual_severity = "low"
                        elif cmd_is_tainted:
                            actual_severity = "critical"
                    
                    # 2. open() 相关：检查模式
                    elif func_base == "open":
                        mode = self._get_open_mode(node)
                        if mode in ("r", "rb", None):  # 只读或默认模式
                            actual_severity = "info"
                        elif mode in ("w", "wb", "a", "ab"):
                            if is_tainted:
                                actual_severity = "high"
                            elif all_args_constant:
                                actual_severity = "low"
                            else:
                                actual_severity = "medium"
                    
                    # 3. makedirs, remove 等文件操作
                    elif func_base in ("makedirs", "remove", "unlink", "rmdir"):
                        if all_args_constant and not is_tainted:
                            actual_severity = "info"
                        elif not is_tainted:
                            actual_severity = "low"
                    
                    # 4. 其他通用规则
                    elif all_args_constant and not is_tainted:
                        if actual_severity == "critical" and func_base not in ("exec", "eval", "compile"):
                            actual_severity = "medium"
                        elif actual_severity == "high":
                            actual_severity = "low"
                        elif actual_severity == "medium":
                            actual_severity = "info"

                    # 如果用户输入流入危险函数，提升严重度（覆盖以上所有降级）
                    # 例外：对于 subprocess，只有命令参数受污染才提升
                    if is_tainted:
                        skip_taint_override = False
                        if func_base in ("run", "call", "check_output", "check_call", "Popen"):
                            # 对 subprocess，只有命令参数(第一个参数)受污染才提升
                            cmd_tainted = node.args and self._is_tainted(node.args[0])
                            if not cmd_tainted:
                                skip_taint_override = True
                        
                        if not skip_taint_override:
                            sev_order = {"info": 0, "safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                            if sev_order.get(actual_severity, 0) < sev_order.get("high", 3):
                                actual_severity = "high"

                    taint_note = ""
                    if is_tainted:
                        taint_note = " [TAINTED: user input flows into this call]"
                    elif all_args_constant:
                        taint_note = " [HARDCODED: all arguments are constants]"

                    finding = Finding(
                        file=self.filepath,
                        line=lineno,
                        severity=actual_severity.upper(),
                        category=self._categorize(call_name),
                        rule_id=f"PY-{severity_name.upper()[:4]}-{lineno:04d}",
                        title=f"Dangerous call: {call_name}()",
                        description=f"{rules['description']}{taint_note}",
                        code_context=self._extract_context(lineno),
                        is_user_input_tainted=is_tainted,
                        confidence=0.9 if is_tainted else (0.5 if all_args_constant else 0.7),
                    )
                    self.findings.append(finding)

        # 混淆检测
        if call_name in ("eval", "exec", "getattr", "setattr", "compile"):
            self.obfuscation_score += 0.3
        if call_name in ("base64.b64decode", "base64.decodebytes"):
            self.obfuscation_score += 0.4
        if call_name == "chr":
            self.obfuscation_score += 0.15  # 单个 chr 不一定是混淆
        if call_name in ("importlib.import_module",):
            self.obfuscation_score += 0.3

        self.generic_visit(node)

    def _all_args_constant(self, node) -> bool:
        """检查函数调用的所有参数是否为编译时常量"""
        for arg in node.args:
            if not self._is_constant(arg):
                return False
        for kw in node.keywords:
            if not self._is_constant(kw.value):
                return False
        return True

    def _is_constant(self, node) -> bool:
        """检查节点是否为常量值"""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.List) and all(self._is_constant(e) for e in node.elts):
            return True
        if isinstance(node, ast.Tuple) and all(self._is_constant(e) for e in node.elts):
            return True
        if isinstance(node, ast.Dict):
            return (all(self._is_constant(k) for k in node.keys if k) and
                    all(self._is_constant(v) for v in node.values))
        # f-strings with only constants
        if isinstance(node, ast.JoinedStr):
            return all(
                isinstance(v, ast.Constant) or
                (isinstance(v, ast.FormattedValue) and self._is_constant(v.value))
                for v in node.values
            )
        # Negative numbers: -1, -3.14
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return isinstance(node.operand, ast.Constant)
        return False

    def _has_kwarg_value(self, node, kwarg_name: str, value) -> bool:
        """检查函数调用是否有特定的关键字参数值"""
        for kw in node.keywords:
            if kw.arg == kwarg_name:
                if isinstance(kw.value, ast.Constant) and kw.value.value == value:
                    return True
                if isinstance(kw.value, ast.NameConstant):
                    return getattr(kw.value, 'value', None) == value
        return False

    def _get_open_mode(self, node) -> str:
        """获取 open() 调用的文件模式"""
        # open(path, mode, ...) - mode 是第二个位置参数
        if len(node.args) >= 2:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                return mode_arg.value
        # 或者 open(path, mode=...)
        for kw in node.keywords:
            if kw.arg == "mode":
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    return kw.value.value
        return None  # 默认模式 = "r"

    def _categorize(self, call_name: str) -> str:
        categories = {
            "code_execution": ["eval", "exec", "compile", "__import__", "importlib"],
            "system_command": ["system", "popen", "call", "run", "check_output", "subprocess", "Popen"],
            "file_operations": ["open", "remove", "unlink", "rmdir", "makedirs", "write", "shutil"],
            "network": ["request", "urlopen", "urlretrieve", "fetch", "socket", "connect",
                       "urllib", "requests.", "httpx.", "aiohttp"],
            "reflection": ["getattr", "setattr", "delattr", "globals", "locals"],
            "deserialization": ["pickle", "marshal", "yaml.load", "loads"],
        }
        for cat, keywords in categories.items():
            if any(k in call_name for k in keywords):
                return cat
        return "other"


# === 优化5: 安全防护模式 ===
# 检测代码中已有的安全措施，用于标注（不降级 severity）
SAFEGUARD_PATTERNS = [
    (r"ip\.is_private|ip\.is_loopback|ip\.is_reserved", "SSRF_PROTECTION",
     "SSRF prevention: blocks private/loopback/reserved IPs"),
    (r"ipaddress\.ip_address.*is_private", "SSRF_PROTECTION",
     "SSRF prevention via ipaddress module"),
    (r"os\.path\.realpath.*startswith|os\.path\.abspath.*startswith", "PATH_TRAVERSAL_CHECK",
     "Path traversal prevention: validates resolved path prefix"),
    (r"if\s+.*\.\.\.* in .*path|if\s+.*path.*\.\.", "PATH_TRAVERSAL_CHECK",
     "Path traversal check: detects directory traversal sequences"),
    (r"(shlex\.quote|shlex\.split|pipes\.quote)", "SHELL_INJECTION_GUARD",
     "Shell injection prevention: uses proper argument quoting"),
    (r"re\.match.*https?://|urlparse.*scheme.*not.*in", "URL_VALIDATION",
     "URL scheme validation: restricts allowed protocols"),
]


def _detect_safeguards(content: str, lines: list[str]) -> list[dict]:
    """检测文件中已有的安全防护措施。返回 [{type, description, line}]"""
    safeguards = []
    for pattern, sg_type, sg_desc in SAFEGUARD_PATTERNS:
        for i, line in enumerate(lines):
            if re.search(pattern, line):
                safeguards.append({
                    "type": sg_type,
                    "description": sg_desc,
                    "line": i + 1,
                })
                break  # 每种防护在每个文件只记录一次
    return safeguards


def _annotate_findings_with_safeguards(findings: list[Finding], safeguards: list[dict]) -> None:
    """将检测到的安全防护信息标注到相关 finding 上（不降级 severity）。
    
    标注格式: [SAFEGUARD_DETECTED: <type> at line X — verify effectiveness]
    """
    if not safeguards:
        return
    
    # 按类型关联：网络相关 finding ↔ SSRF 防护，文件相关 ↔ 路径防护
    sg_category_map = {
        "SSRF_PROTECTION": {"network", "other"},
        "PATH_TRAVERSAL_CHECK": {"file_operations", "other"},
        "SHELL_INJECTION_GUARD": {"system_command", "code_execution"},
        "URL_VALIDATION": {"network", "other"},
    }
    
    for sg in safeguards:
        related_categories = sg_category_map.get(sg["type"], set())
        for f in findings:
            if f.category in related_categories or not related_categories:
                annotation = (f" [SAFEGUARD_DETECTED: {sg['type']} at line {sg['line']}" 
                            f" — verify effectiveness: {sg['description']}]")
                if annotation not in f.description:
                    f.description += annotation


def analyze_python_file(filepath: str, lines: list[str]) -> StaticAnalysisResult:
    """分析单个 Python 文件"""
    result = StaticAnalysisResult(file=filepath, language="python")
    content = "\n".join(lines)

    # 1. AST 分析
    try:
        tree = ast.parse(content, filename=filepath)
        visitor = EnhancedPythonVisitor(filepath, lines)
        visitor.visit(tree)
        result.findings = visitor.findings
        result.obfuscation_score = visitor.obfuscation_score
    except SyntaxError as e:
        result.error = f"AST parse failed: {e}"

    # 2. 正则补充检查（AST 可能遗漏的模式）
    for pattern_name, pattern_config in OBFUSCATION_PATTERNS.items():
        matches = re.findall(pattern_config["pattern"], content)
        if len(matches) >= pattern_config["threshold"]:
            result.obfuscation_score += 0.3
            result.obfuscation_details.append({
                "pattern": pattern_name,
                "count": len(matches),
                "description": pattern_config["description"],
            })

    # 3. 逐行正则扫描（捕获 AST 无法检测到的网络模式）
    network_patterns = [
        (r"urllib\.request\.(urlopen|Request|urlretrieve)\s*\(", "urllib_request", "HIGH"),
        (r"requests\.(get|post|put|delete|patch|head)\s*\(", "requests_call", "HIGH"),
        (r"httpx\.(get|post|put|delete|patch|head)\s*\(", "httpx_call", "HIGH"),
        (r"aiohttp\.ClientSession", "aiohttp_session", "MEDIUM"),
    ]

    existing_lines = {f.line for f in result.findings if hasattr(f, 'line')}

    for i, line in enumerate(lines):
        lineno = i + 1
        if lineno in existing_lines:
            continue  # 已经有 AST finding 了
        for pattern, name, severity in network_patterns:
            if re.search(pattern, line):
                context = _extract_context_lines(lines, lineno)
                finding = Finding(
                    file=filepath,
                    line=lineno,
                    severity=severity,
                    category="network",
                    rule_id=f"PY-NET-{lineno:04d}",
                    title=f"Network operation: {name}",
                    description=f"Network request detected - potential data exfiltration vector",
                    code_context=context,
                    confidence=0.6,
                )
                result.findings.append(finding)

    # 4. 安全防护标注（不降级 severity，只添加注释）
    safeguards = _detect_safeguards(content, lines)
    if safeguards:
        _annotate_findings_with_safeguards(result.findings, safeguards)

    return result


def _extract_context_lines(lines: list[str], lineno: int, window: int = 5) -> str:
    """提取代码上下文"""
    start = max(0, lineno - 1 - window)
    end = min(len(lines), lineno + window)
    context_lines = []
    for i in range(start, end):
        marker = ">>> " if i == lineno - 1 else "    "
        context_lines.append(f"{marker}{i + 1:4d} | {lines[i].rstrip()}")
    return "\n".join(context_lines)


# ============================================================
# JavaScript / TypeScript 分析
# ============================================================

def analyze_js_file(filepath: str, lines: list[str]) -> StaticAnalysisResult:
    """分析 JS/TS 文件（正则模式匹配）"""
    result = StaticAnalysisResult(file=filepath, language="javascript")
    content = "\n".join(lines)

    for severity_name, rules in JS_DANGER_RULES.items():
        for pattern, type_name in rules["patterns"]:
            for i, line in enumerate(lines):
                if re.search(pattern, line):
                    start = max(0, i - 5)
                    end = min(len(lines), i + 6)
                    context_lines = []
                    for j in range(start, end):
                        marker = ">>> " if j == i else "    "
                        context_lines.append(f"{marker}{j + 1:4d} | {lines[j].rstrip()}")

                    finding = Finding(
                        file=filepath,
                        line=i + 1,
                        severity=severity_name.upper(),
                        category="js_" + type_name.replace(" ", "_").replace("()", ""),
                        rule_id=f"JS-{severity_name.upper()[:4]}-{i + 1:04d}",
                        title=f"Dangerous pattern: {type_name}",
                        description=rules["description"],
                        code_context="\n".join(context_lines),
                        confidence=0.6,  # 正则匹配置信度较低
                    )
                    result.findings.append(finding)

    # 混淆检测
    eval_count = len(re.findall(r"eval\s*\(", content))
    hex_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", content))
    if eval_count > 3:
        result.obfuscation_score += 0.5
        result.obfuscation_details.append({"pattern": "excessive_eval", "count": eval_count})
    if hex_count > 10:
        result.obfuscation_score += 0.4
        result.obfuscation_details.append({"pattern": "hex_escapes", "count": hex_count})

    return result


# ============================================================
# 依赖分析
# ============================================================

def analyze_dependencies(filepath: str, content: str) -> list[dict]:
    """检查依赖文件中的已知恶意包和 typo-squatting"""
    issues = []
    filename = os.path.basename(filepath)

    if filename == "requirements.txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg_name = re.split(r"[>=<!\[]", line)[0].strip().lower()
            for malicious in KNOWN_MALICIOUS_PACKAGES["python"]:
                if pkg_name == malicious.lower():
                    issues.append({
                        "type": "known_malicious",
                        "package": pkg_name,
                        "severity": "CRITICAL",
                        "description": f"Known malicious package: {pkg_name}",
                    })
                # 简单的 typo-squatting 检测（编辑距离）
                elif _levenshtein(pkg_name, malicious.lower()) == 1:
                    issues.append({
                        "type": "typo_squatting_suspect",
                        "package": pkg_name,
                        "similar_to": malicious,
                        "severity": "HIGH",
                        "description": f"Possible typo-squatting: '{pkg_name}' similar to known malicious '{malicious}'",
                    })

    elif filename == "package.json":
        try:
            pkg_data = json.loads(content)
            all_deps = {}
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                all_deps.update(pkg_data.get(key, {}))

            for dep_name in all_deps:
                for malicious in KNOWN_MALICIOUS_PACKAGES["npm"]:
                    if dep_name.lower() == malicious.lower():
                        issues.append({
                            "type": "known_malicious",
                            "package": dep_name,
                            "severity": "CRITICAL",
                            "description": f"Known compromised npm package: {dep_name}",
                        })

            # 检查可疑的 scripts
            scripts = pkg_data.get("scripts", {})
            for script_name, script_cmd in scripts.items():
                if any(danger in script_cmd for danger in ["curl ", "wget ", "rm -rf", "eval ", "base64"]):
                    issues.append({
                        "type": "suspicious_script",
                        "script": script_name,
                        "command": script_cmd[:200],
                        "severity": "HIGH",
                        "description": f"Suspicious npm script '{script_name}': {script_cmd[:100]}",
                    })
        except json.JSONDecodeError:
            pass

    return issues


def _levenshtein(s1: str, s2: str) -> int:
    """简单的编辑距离计算"""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


# ============================================================
# 统一入口
# ============================================================

# ============================================================
# Shell 脚本分析
# ============================================================

def _is_inside_echo_quotes(line: str, pattern_match_start: int) -> bool:
    """检查模式匹配位置是否严格在 echo 的引号字符串内部（纯文本输出）。
    
    注意：这里的判断比较保守，只有匹配被完全包含在引号中时才返回 True。
    例如 `echo "curl ... | bash"` → True
    但 `echo "hi" && curl ... | bash` → False（管道在引号外）
    """
    stripped = line.strip()
    if not re.match(r'^echo\s', stripped):
        return False
    
    # 找到 echo 后的内容
    echo_rest = stripped[4:].strip()
    
    # 检查 curl|bash 部分是否严格在引号内
    # 简单方法：整个 echo 参数被引号包裹，且引号在 curl|bash 之前和之后
    if (echo_rest.startswith('"') and echo_rest.endswith('"')) or \
       (echo_rest.startswith("'") and echo_rest.endswith("'")):
        # 额外安全检查：引号内不含命令替换 $(...) 或 `...`
        inner = echo_rest[1:-1]
        if '$(' not in inner and '`' not in inner:
            return True
    return False


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """按 (rule_name/title, file) 去重 findings，保留所有代码上下文。
    
    不同行号但同规则同文件的 findings 合并为一条：
    - line 取第一个
    - code_context 保留所有实例（分隔线隔开）
    - description 追加全部行号
    - severity 取最高
    """
    from collections import OrderedDict
    
    groups: OrderedDict[str, list[Finding]] = OrderedDict()
    for f in findings:
        key = (f.title, f.file)
        groups.setdefault(key, []).append(f)
    
    deduped = []
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "SAFE": 0}
    
    for key, group in groups.items():
        if len(group) == 1:
            deduped.append(group[0])
            continue
        
        # 取最高 severity
        best_sev = max(group, key=lambda f: severity_order.get(f.severity, 0)).severity
        
        # 合并行号
        all_lines = [f.line for f in group]
        lines_str = ", ".join(str(l) for l in all_lines)
        
        # 合并代码上下文（保留每个实例的片段）
        all_contexts = []
        for f in group:
            all_contexts.append(f"--- Line {f.line} ---\n{f.code_context}")
        merged_context = "\n\n".join(all_contexts)
        
        merged = Finding(
            file=group[0].file,
            line=group[0].line,
            severity=best_sev,
            category=group[0].category,
            rule_id=group[0].rule_id,
            title=group[0].title,
            description=f"{group[0].description} [×{len(group)} occurrences at lines: {lines_str}]",
            code_context=merged_context,
            confidence=max(f.confidence for f in group),
        )
        deduped.append(merged)
    
    return deduped


def analyze_shell_file(filepath: str, lines: list[str]) -> StaticAnalysisResult:
    """分析 Shell 脚本（.sh, .bash 及无扩展名但有 shebang 的文件）"""
    result = StaticAnalysisResult(file=filepath, language="shell")
    content = "\n".join(lines)

    for severity_name, rules in SHELL_DANGER_RULES.items():
        for pattern_tuple in rules["patterns"]:
            pattern, rule_name, detail_desc = pattern_tuple

            for i, line in enumerate(lines):
                # 跳过注释行
                stripped = line.strip()
                if stripped.startswith("#") and not stripped.startswith("#!"):
                    continue

                # === 优化1: shebang 行排除 env_access ===
                # #!/usr/bin/env bash 是解释器声明，不是"访问环境变量"
                if rule_name == "env_access" and stripped.startswith("#!"):
                    continue

                if re.search(pattern, line):
                    lineno = i + 1
                    actual_desc = detail_desc

                    # === 优化2: echo 上下文标注（不降级） ===
                    # 如果 curl|bash 严格在 echo 引号内且无命令替换，
                    # 标注让 LLM 审查，但保持原始 severity
                    if rule_name in ("curl_pipe_shell", "wget_pipe_shell"):
                        if _is_inside_echo_quotes(line, 0):
                            actual_desc += (" [ECHO_CONTEXT: pattern appears inside "
                                          "echo quoted string — LLM should verify "
                                          "if this is documentation or actual execution]")

                    # 提取上下文
                    start = max(0, i - 5)
                    end = min(len(lines), i + 6)
                    context_lines = []
                    for j in range(start, end):
                        marker = ">>> " if j == i else "    "
                        context_lines.append(f"{marker}{j + 1:4d} | {lines[j].rstrip()}")

                    finding = Finding(
                        file=filepath,
                        line=lineno,
                        severity=severity_name.upper(),
                        category=f"shell_{rule_name}",
                        rule_id=f"SH-{severity_name.upper()[:4]}-{lineno:04d}",
                        title=f"Shell: {rule_name}",
                        description=actual_desc,
                        code_context="\n".join(context_lines),
                        confidence=0.75,
                    )
                    result.findings.append(finding)

    # === 优化3: Finding 去重（保留所有代码上下文） ===
    result.findings = _deduplicate_findings(result.findings)

    # 混淆检测：shell 脚本中的 base64、hex、变量拼接等
    base64_count = len(re.findall(r"base64\s+(-d|--decode)", content))
    hex_escape_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", content))
    eval_count = len(re.findall(r"\beval\b", content))

    if base64_count >= 2 or hex_escape_count >= 5 or eval_count >= 3:
        result.obfuscation_score = 0.6
        result.obfuscation_details.append({
            "pattern": "shell_obfuscation",
            "counts": {"base64_decode": base64_count, "hex_escapes": hex_escape_count, "eval": eval_count},
            "description": "Shell script contains obfuscation patterns",
        })

    return result


def _has_shell_shebang(filepath: str) -> bool:
    """检查无扩展名文件是否有 shell shebang"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            first_line = f.readline(200)
        return bool(re.match(r"^#!\s*/(?:usr/)?(?:bin/)?(bash|sh|zsh|dash|ksh)", first_line))
    except Exception:
        return False


LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".sh": "shell",
    ".bash": "shell",
    ".json": "tool_config",
    ".yml": "tool_config",
    ".yaml": "tool_config",
}

PACKAGE_FILES = {"requirements.txt", "package.json", "Pipfile", "pyproject.toml"}

# Import skill prompt rules
try:
    from configs.audit_config import SKILL_PROMPT_RULES, SKILL_MD_PATTERNS, SKILL_DIR_PATTERNS
except ImportError:
    SKILL_PROMPT_RULES = {}
    SKILL_MD_PATTERNS = []
    SKILL_DIR_PATTERNS = []


# ============================================================
# Skill Prompt (.md) 分析
# ============================================================

def _is_skill_md(filepath: str) -> bool:
    """判断一个 .md 文件是否是 skill/agent 指令文件（而非普通文档）"""
    filename = os.path.basename(filepath)
    dirpath = os.path.dirname(filepath).replace("\\", "/").lower()

    # 1. 文件名匹配
    if filename in SKILL_MD_PATTERNS or filename.upper() in [p.upper() for p in SKILL_MD_PATTERNS]:
        return True

    # 2. 父目录匹配
    dir_parts = dirpath.split("/")
    for part in dir_parts:
        if part.lower() in SKILL_DIR_PATTERNS:
            return True

    # 3. 内容启发式：检查文件前 500 字符是否包含 skill 关键词
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(500).lower()
        skill_keywords = ["# skill", "## overview", "you are", "your role", "your task",
                         "when the user", "instructions:", "## capabilities",
                         "## commands", "/command", "## workflow", "as an ai",
                         "as a specialized", "you will", "you should"]
        matches = sum(1 for kw in skill_keywords if kw in head)
        return matches >= 2  # 至少匹配 2 个关键词
    except Exception:
        return False


def analyze_skill_md(filepath: str, lines: list[str]) -> StaticAnalysisResult:
    """分析 Skill Prompt (.md) 文件中的潜在恶意指令"""
    result = StaticAnalysisResult(file=filepath, language="skill_prompt")
    content = "\n".join(lines)

    for severity_name, rules in SKILL_PROMPT_RULES.items():
        for pattern_tuple in rules["patterns"]:
            pattern, rule_name, detail_desc = pattern_tuple

            # 对 .md 文件用多行匹配
            for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                # 找到匹配所在的行号
                line_start = content[:match.start()].count("\n") + 1

                # 提取上下文
                start = max(0, line_start - 1 - 3)
                end = min(len(lines), line_start + 4)
                context_lines = []
                for j in range(start, end):
                    marker = ">>> " if j == line_start - 1 else "    "
                    context_lines.append(f"{marker}{j + 1:4d} | {lines[j].rstrip()}")

                finding = Finding(
                    file=filepath,
                    line=line_start,
                    severity=severity_name.upper(),
                    category=f"skill_prompt_{rule_name}",
                    rule_id=f"SK-{severity_name.upper()[:4]}-{line_start:04d}",
                    title=f"Skill Prompt: {rule_name}",
                    description=detail_desc,
                    code_context="\n".join(context_lines),
                    confidence=0.65,  # prompt 分析置信度低于代码分析
                )
                result.findings.append(finding)

                # 每个规则每文件只报一次（避免重复 finding 刷屏）
                break

    return result


def analyze_tool_config(filepath: str, lines: list[str]) -> StaticAnalysisResult:
    """分析 Tool 配置 (.json, .yml) 寻找高危权限声明"""
    result = StaticAnalysisResult(file=filepath, language="tool_config")
    content = "\n".join(lines)
    
    parsed_config = None
    ext = os.path.splitext(filepath)[1].lower()
    
    try:
        if ext == ".json":
            parsed_config = json.loads(content)
        elif ext in (".yml", ".yaml"):
            parsed_config = yaml.safe_load(content)
    except Exception as e:
        result.error = f"Failed to parse config: {e}"
        return result
        
    if not isinstance(parsed_config, (dict, list)):
        return result

    # Flatten structure and search for dangerous capabilities
    # e.g looking for commands containing 'shell', 'exec', 'subprocess'
    dangerous_keywords = {"shell", "exec", "subprocess", "bash", "system", "run_command"}
    
    def search_dict(d, path=""):
        if isinstance(d, dict):
            for k, v in d.items():
                if isinstance(v, (dict, list)):
                    search_dict(v, f"{path}.{k}" if path else k)
                elif isinstance(v, str):
                    if k.lower() in ("command", "permissions", "type", "name", "tool") or "cmd" in k.lower():
                        v_lower = v.lower()
                        for kw in dangerous_keywords:
                            if kw in v_lower:
                                finding = Finding(
                                    file=filepath,
                                    line=1, # Config files might not easily give line numbers from parsed dict
                                    severity="HIGH",
                                    category="tool_permission",
                                    rule_id=f"CFG-HIGH-0001",
                                    title=f"Dangerous tool capability",
                                    description=f"Configured capability '{kw}' found in property '{path}.{k}': {v}",
                                    code_context=f"{k}: {v}",
                                    confidence=0.8,
                                )
                                result.findings.append(finding)
        elif isinstance(d, list):
            for i, item in enumerate(d):
                if isinstance(item, (dict, list)):
                    search_dict(item, f"{path}[{i}]")
                    
    search_dict(parsed_config)
    return result


def analyze_file(filepath: str) -> Optional[StaticAnalysisResult]:
    """分析单个文件，自动选择分析器"""
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception as e:
        return StaticAnalysisResult(file=filepath, language="unknown", error=str(e))

    # 依赖文件
    if filename in PACKAGE_FILES:
        result = StaticAnalysisResult(file=filepath, language="dependency")
        result.dependency_issues = analyze_dependencies(filepath, content)
        return result

    # Skill Prompt 文件 (.md)
    if ext == ".md" and _is_skill_md(filepath):
        result = analyze_skill_md(filepath, lines)
        # 即使没有 finding，也返回结果（计入 files_analyzed）
        return result

    # 已知代码扩展名
    lang = LANG_MAP.get(ext)

    # 无扩展名文件：检查 shebang
    if not lang and ext in ("", None, "(no ext)"):
        if _has_shell_shebang(filepath):
            lang = "shell"

    if not lang:
        return None

    if lang == "python":
        return analyze_python_file(filepath, lines)
    elif lang == "shell":
        return analyze_shell_file(filepath, lines)
    elif lang == "tool_config":
        return analyze_tool_config(filepath, lines)
    else:
        return analyze_js_file(filepath, lines)


# 已知的源代码扩展名 → 语言名称（包括不支持的）
ALL_CODE_EXTENSIONS = {
    # 支持的
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".jsx": "React JSX", ".tsx": "React TSX", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".sh": "Shell", ".bash": "Shell",
    # 不支持的
    ".swift": "Swift", ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
    ".cs": "C#", ".cpp": "C++", ".c": "C", ".h": "C/C++ Header",
    ".hpp": "C++ Header", ".m": "Objective-C", ".mm": "Objective-C++",
    ".php": "PHP", ".r": "R", ".R": "R",
    ".scala": "Scala", ".clj": "Clojure", ".ex": "Elixir",
    ".exs": "Elixir", ".erl": "Erlang", ".hs": "Haskell",
    ".lua": "Lua", ".pl": "Perl", ".pm": "Perl",
    ".dart": "Dart", ".zig": "Zig", ".nim": "Nim",
    ".v": "V", ".jl": "Julia", ".sol": "Solidity",
}

SUPPORTED_CODE_EXTENSIONS = set(LANG_MAP.keys())


@dataclass
class ScanStats:
    """扫描统计信息"""
    total_files_walked: int = 0
    files_analyzed: int = 0
    files_skipped_type: int = 0       # 不支持的文件类型
    files_skipped_size: int = 0       # 超过大小限制
    files_skipped_error: int = 0      # 读取错误
    file_type_counts: dict = field(default_factory=dict)  # 按扩展名统计
    analyzed_type_counts: dict = field(default_factory=dict)  # 实际分析的

    # 核心语言覆盖度分析
    dominant_language: str = ""          # 仓库的主语言（按代码文件数量）
    dominant_language_supported: bool = True  # 主语言是否被支持
    code_files_total: int = 0            # 仓库中所有源代码文件数量
    code_files_analyzed: int = 0         # 被分析的源代码文件数量
    code_coverage_ratio: float = 1.0     # 代码覆盖率 = analyzed / total
    unsupported_code_counts: dict = field(default_factory=dict)  # 未支持的代码语言统计
    is_low_coverage: bool = False        # 覆盖率是否过低（< 50%）
    is_prompt_based: bool = False        # 是否为 prompt-based skill（主要由 .md 构成）
    skill_prompts_analyzed: int = 0      # 被分析的 skill prompt 文件数

    def to_dict(self):
        return asdict(self)

    def compute_coverage(self):
        """根据 file_type_counts 和 analyzed_type_counts 计算语言覆盖度"""
        supported_count = 0
        unsupported_count = 0
        unsupported_langs = {}

        for ext, count in self.file_type_counts.items():
            if ext in SUPPORTED_CODE_EXTENSIONS:
                supported_count += count
            elif ext in ALL_CODE_EXTENSIONS:
                unsupported_count += count
                lang_name = ALL_CODE_EXTENSIONS[ext]
                unsupported_langs[lang_name] = unsupported_langs.get(lang_name, 0) + count

        # skill_prompt 文件也算"有效分析"
        self.skill_prompts_analyzed = self.analyzed_type_counts.get("skill_prompt", 0)

        self.code_files_total = supported_count + unsupported_count
        # code_files_analyzed = 传统代码 + skill prompt
        dep_count = self.analyzed_type_counts.get("dependency", 0)
        self.code_files_analyzed = self.files_analyzed - dep_count
        self.unsupported_code_counts = unsupported_langs

        # 判断是否为 prompt-based skill 仓库
        # 特征：大量 .md 文件，skill_prompt 被分析数 > 传统代码文件数
        md_count = self.file_type_counts.get(".md", 0)
        traditional_code = self.code_files_analyzed - self.skill_prompts_analyzed
        if self.skill_prompts_analyzed > 0 and (
            self.skill_prompts_analyzed >= traditional_code or md_count > supported_count
        ):
            self.is_prompt_based = True

        # 覆盖率计算
        # 对 prompt-based 仓库：分析了 skill prompt + 少量脚本 = 高覆盖
        if self.is_prompt_based:
            # prompt 仓库的"有效代码"= skill_prompt + 传统代码
            total_meaningful = self.skill_prompts_analyzed + supported_count + unsupported_count
            if total_meaningful > 0:
                self.code_coverage_ratio = self.code_files_analyzed / total_meaningful
            else:
                self.code_coverage_ratio = 1.0
        elif self.code_files_total > 0:
            self.code_coverage_ratio = self.code_files_analyzed / self.code_files_total
        else:
            self.code_coverage_ratio = 1.0

        # 找出主语言（对 prompt-based 仓库，主语言标记为 Skill Prompt）
        all_lang_counts = {}
        for ext, count in self.file_type_counts.items():
            if ext in ALL_CODE_EXTENSIONS:
                lang = ALL_CODE_EXTENSIONS[ext]
                all_lang_counts[lang] = all_lang_counts.get(lang, 0) + count

        # 如果 skill_prompt 被分析了，加入语言统计
        if self.skill_prompts_analyzed > 0:
            all_lang_counts["Skill Prompt (MD)"] = self.skill_prompts_analyzed

        if all_lang_counts:
            self.dominant_language = max(all_lang_counts, key=all_lang_counts.get)
            if self.dominant_language == "Skill Prompt (MD)":
                self.dominant_language_supported = True  # 我们支持 skill prompt 分析
            else:
                dominant_exts = [ext for ext, lang in ALL_CODE_EXTENSIONS.items()
                              if lang == self.dominant_language]
                self.dominant_language_supported = any(
                    ext in SUPPORTED_CODE_EXTENSIONS for ext in dominant_exts
                )
        else:
            self.dominant_language = "N/A"
            self.dominant_language_supported = True

        # 低覆盖率判定
        self.is_low_coverage = (
            self.code_files_total > 5 and self.code_coverage_ratio < 0.5
            and not self.is_prompt_based  # prompt-based 仓库不算低覆盖
        )


def analyze_repo(repo_path: str, max_file_size_kb: int = 500) -> tuple[list[StaticAnalysisResult], ScanStats]:
    """
    扫描整个仓库。
    返回 (results, stats) — stats 包含详细的扫描统计。
    """
    results = []
    stats = ScanStats()
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox",
                 ".mypy_cache", ".pytest_cache", ".eggs", "egg-info", ".nox"}

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]

        for filename in files:
            filepath = os.path.join(root, filename)
            stats.total_files_walked += 1

            # 统计文件类型
            ext = os.path.splitext(filename)[1].lower() or "(no ext)"
            stats.file_type_counts[ext] = stats.file_type_counts.get(ext, 0) + 1

            # 跳过过大的文件
            try:
                if os.path.getsize(filepath) > max_file_size_kb * 1024:
                    stats.files_skipped_size += 1
                    continue
            except OSError:
                stats.files_skipped_error += 1
                continue

            result = analyze_file(filepath)
            if result:
                result.file = os.path.relpath(filepath, repo_path)
                results.append(result)
                stats.files_analyzed += 1
                lang = result.language if hasattr(result, 'language') else "unknown"
                stats.analyzed_type_counts[lang] = stats.analyzed_type_counts.get(lang, 0) + 1
            else:
                stats.files_skipped_type += 1

    # 计算覆盖度
    stats.compute_coverage()

    return results, stats
