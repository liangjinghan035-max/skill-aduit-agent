"""
审计配置：索引仓库、审计参数、模型配置
"""

# ============================================================
# 审计数据源 —— 两个 awesome-list 索引仓库
# 流程：克隆索引仓库 → 提取 .md 中的 GitHub 链接 → 选取 skill → 深度审计
# ============================================================

INDEX_REPOS = [
    {
        "url": "https://github.com/VoltAgent/awesome-openclaw-skills",
        "name": "awesome-openclaw-skills",
        "description": "VoltAgent 开源 Claw skill 合集",
    },
    {
        "url": "https://github.com/VoltAgent/awesome-agent-skills",
        "name": "awesome-agent-skills",
        "description": "VoltAgent Agent skill 合集",
    },
]

# 从索引仓库提取链接时，忽略这些（索引本身、通用框架等）
LINK_IGNORE_PATTERNS = [
    "awesome-openclaw-skills",
    "awesome-agent-skills",
    "VoltAgent/voltagent",       # 框架本身，不是 skill
    "github.com/features",
    "github.com/topics",
    "github.com/settings",
]

# 批量审计时，最多审计多少个 skill（0 = 不限）
MAX_SKILLS_PER_RUN = 20


# ============================================================
# 审计模型配置
# ============================================================

AUDIT_AGENT_VERSION = "V1"

# OpenRouter 配置
# 设置环境变量: export OPENROUTER_API_KEY="sk-or-v1-..."
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

# Gold Agent: 三个角色用不同模型做交叉验证，提高准确性
# 你可以根据预算和偏好换模型，完整列表见 https://openrouter.ai/models
LLM_CONFIGS = {
    "security_analyst": {
        "provider": "openrouter",
        "model": "anthropic/claude-sonnet-4.6",  # 安全分析 — Claude Sonnet 4.6
        "role": "Focused on identifying security vulnerabilities and attack vectors",
        "temperature": 0.1,
    },
    "intent_analyst": {
        "provider": "openrouter",
        "model": "openai/gpt-5.3-codex",  # 意图分析 — GPT Codex 5.3
        "role": "Focused on understanding code intent and distinguishing bugs from features",
        "temperature": 0.2,
    },
    "adversarial_analyst": {
        "provider": "openrouter",
        "model": "google/gemini-3.1-pro-preview",  # 红队模拟 — Gemini 3.1 Pro
        "role": "Red team perspective - simulates attack scenarios",
        "temperature": 0.3,
    },
}

# Fast Agent 配置（Phase 3 用，便宜快速）
FAST_LLM_CONFIG = {
    "provider": "openrouter",
    "model": "anthropic/claude-sonnet-4.6",
    "temperature": 0.1,
}


# ============================================================
# 静态分析规则（扩展版）
# ============================================================

# Python 危险函数分类（按严重程度）
PYTHON_DANGER_RULES = {
    "critical": {
        "functions": {"exec", "eval", "compile", "__import__"},
        "modules": {},
        "patterns": [
            r"exec\s*\(",
            r"eval\s*\(",
            r"__import__\s*\(",
            r"compile\s*\(.+,\s*['\"]exec['\"]\)",
        ],
        "description": "Dynamic code execution - can run arbitrary code",
    },
    "high": {
        "functions": {"system", "popen", "call", "run", "check_output", "check_call"},
        "modules": {"os", "subprocess"},
        "patterns": [
            r"os\.system\s*\(",
            r"subprocess\.(run|call|Popen|check_output)\s*\(",
            r"os\.popen\s*\(",
            r"shutil\.rmtree\s*\(",
        ],
        "description": "System command execution - can interact with OS",
    },
    "medium": {
        "functions": {"open", "remove", "unlink", "rmdir", "makedirs", "rename", "chmod"},
        "modules": {"os", "shutil", "pathlib"},
        "patterns": [
            r"open\s*\(.+,\s*['\"]w",
            r"os\.(remove|unlink|rmdir|chmod)\s*\(",
            r"shutil\.(copy|move|rmtree)\s*\(",
            r"pathlib\.Path\(.+\)\.(unlink|rmdir|write_text)\s*\(",
        ],
        "description": "Filesystem modification - can alter/delete files",
    },
    "low": {
        "functions": {"getattr", "setattr", "delattr", "globals", "locals"},
        "modules": {},
        "patterns": [
            r"getattr\s*\(",
            r"setattr\s*\(",
            r"pickle\.loads?\s*\(",
            r"marshal\.loads?\s*\(",
            r"yaml\.load\s*\(",  # unsafe yaml.load without Loader
        ],
        "description": "Reflection/deserialization - potential for code injection",
    },
}

# Network operations (separate category - not inherently dangerous but
# important for exfiltration detection)
PYTHON_NETWORK_RULES = {
    "high": {
        "functions": {"urlopen", "urlretrieve"},
        "modules": {"urllib", "urllib.request"},
        "patterns": [
            r"urllib\.request\.urlopen\s*\(",
            r"urllib\.request\.Request\s*\(",
            r"urllib\.request\.urlretrieve\s*\(",
            r"requests\.(get|post|put|delete|patch)\s*\(",
            r"httpx\.(get|post|put|delete|patch)\s*\(",
            r"aiohttp\.ClientSession\s*\(",
        ],
        "description": "Network request - potential data exfiltration vector",
    },
    "medium": {
        "functions": {"socket", "connect"},
        "modules": {"socket"},
        "patterns": [
            r"socket\.socket\s*\(",
            r"\.connect\s*\(\s*\(",
        ],
        "description": "Raw socket connection",
    },
}

# JavaScript/TypeScript 危险模式
JS_DANGER_RULES = {
    "critical": {
        "patterns": [
            (r"eval\s*\(", "eval()"),
            (r"Function\s*\(", "Function() constructor"),
            (r"new\s+Function\s*\(", "new Function()"),
            (r"setTimeout\s*\(\s*['\"]", "setTimeout with string"),
            (r"setInterval\s*\(\s*['\"]", "setInterval with string"),
        ],
        "description": "Dynamic code execution",
    },
    "high": {
        "patterns": [
            (r"child_process", "child_process module"),
            (r"execSync\s*\(", "execSync()"),
            (r"exec\s*\(", "exec()"),
            (r"spawn\s*\(", "spawn()"),
            (r"spawnSync\s*\(", "spawnSync()"),
        ],
        "description": "System command execution",
    },
    "medium": {
        "patterns": [
            (r"fs\.(writeFile|appendFile|unlink|rmdir|rm)\s*\(", "fs write/delete"),
            (r"fs\.(writeFileSync|appendFileSync|unlinkSync)\s*\(", "fs sync write/delete"),
            (r"fetch\s*\(", "network fetch"),
            (r"axios\.", "axios network request"),
            (r"require\s*\(\s*['\"]https?['\"]", "http module"),
        ],
        "description": "Filesystem/network operations",
    },
    "low": {
        "patterns": [
            (r"\.innerHTML\s*=", "innerHTML assignment (XSS)"),
            (r"document\.write\s*\(", "document.write"),
            (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
        ],
        "description": "DOM manipulation (XSS risk)",
    },
}

# 混淆检测模式
OBFUSCATION_PATTERNS = {
    "base64_heavy": {
        "pattern": r"base64\.(b64decode|b64encode|decodebytes)",
        "threshold": 2,
        "description": "Heavy base64 usage may hide payloads",
    },
    "hex_escapes": {
        "pattern": r"\\x[0-9a-fA-F]{2}",
        "threshold": 10,
        "description": "Excessive hex escapes suggest obfuscation",
    },
    "char_code": {
        "pattern": r"chr\s*\(\s*\d+\s*\)",
        "threshold": 3,
        "description": "Character code construction may hide strings",
    },
    "char_code_chain": {
        "pattern": r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)",
        "threshold": 1,
        "description": "Chained chr() calls to construct strings - strong obfuscation signal",
    },
    "dynamic_import": {
        "pattern": r"__import__\s*\(|importlib\.import_module",
        "threshold": 1,
        "description": "Dynamic imports can load arbitrary modules",
    },
    "string_concat_build": {
        "pattern": r"(\+\s*['\"][a-zA-Z]{1,3}['\"]){3,}",
        "threshold": 3,
        "description": "String concatenation to build identifiers",
    },
    "getattr_chain": {
        "pattern": r"getattr\s*\(\s*getattr\s*\(",
        "threshold": 1,
        "description": "Chained getattr calls for dynamic attribute resolution",
    },
}

# 供应链安全 - 已知恶意包和 typo-squatting 模式
KNOWN_MALICIOUS_PACKAGES = {
    "python": [
        "python3-dateutil",   # typo of python-dateutil
        "jeIlyfish",          # typo of jellyfish (I vs l)
        "python-sqlite",      # fake package
        "requesocks",         # typo of requests
        "colourama",          # typo of colorama
    ],
    "npm": [
        "event-stream",       # compromised
        "flatmap-stream",     # malicious
        "ua-parser-js",       # compromised version
        "coa",                # compromised version
        "rc",                 # compromised version
    ],
}


# ============================================================
# Shell 脚本危险模式
# install.sh / setup.sh 是 `curl | bash` 攻击的经典载体
# ============================================================

SHELL_DANGER_RULES = {
    "critical": {
        "patterns": [
            # 远程下载并执行 — 最高风险
            (r"curl\s+.*\|\s*(bash|sh|zsh|source)", "curl_pipe_shell",
             "Downloads and executes remote script — classic supply chain attack vector"),
            (r"wget\s+.*\|\s*(bash|sh|zsh|source)", "wget_pipe_shell",
             "Downloads and executes remote script"),
            (r"curl\s+.*-o\s+\S+.*&&.*(\./|bash|sh|chmod)", "curl_download_exec",
             "Downloads file then executes it"),
            (r"wget\s+.*-O\s+\S+.*&&.*(\./|bash|sh|chmod)", "wget_download_exec",
             "Downloads file then executes it"),
            # eval 执行变量 / 远程内容
            (r'eval\s+"\$\(curl', "eval_curl",
             "Evaluates remotely fetched content — extremely dangerous"),
            (r'eval\s+"\$\(wget', "eval_wget",
             "Evaluates remotely fetched content — extremely dangerous"),
            # base64 解码执行
            (r"base64\s+(-d|--decode).*\|\s*(bash|sh)", "base64_pipe_shell",
             "Decodes and executes base64 payload — obfuscation technique"),
            # crontab 注入
            (r"crontab\s", "crontab_modify",
             "Modifies scheduled tasks — persistence mechanism"),
            # SSH key 操作
            (r">>?\s*~?/\.ssh/authorized_keys", "ssh_key_inject",
             "Writes to SSH authorized_keys — backdoor installation"),
        ],
        "description": "Remote code execution or persistence mechanisms",
    },
    "high": {
        "patterns": [
            # 系统级修改
            (r"(sudo\s|/etc/sudoers|visudo)", "sudo_usage",
             "Uses or modifies sudo privileges"),
            (r"(systemctl\s+(enable|start|restart)|service\s+\S+\s+(start|restart))", "systemd_modify",
             "Installs or starts system services"),
            (r"(/etc/profile|/etc/bashrc|~?/\.(bashrc|zshrc|profile|bash_profile))\b", "shell_profile_modify",
             "Modifies shell profile — code runs on every login"),
            # 网络下载（不直接执行但仍需关注）
            (r"curl\s+(-[fsSLkO])*\s*https?://", "curl_download",
             "Downloads from remote URL"),
            (r"wget\s+(-[qcO])*\s*https?://", "wget_download",
             "Downloads from remote URL"),
            # 敏感目录写入
            (r">\s*/etc/", "write_etc",
             "Writes to /etc/ system configuration"),
            (r"cp\s+.*\s+/usr/(local/)?bin/", "install_binary",
             "Installs binary to system PATH"),
            # 凭据明文写入 — 匹配赋值/持久化动作，不匹配 echo 提示文字
            (r"""['"]?(PASSWORD|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY)['"]?\s*[:=]\s*['"]?\$\{?\w""",
             "credential_in_variable",
             "Assigns credential value to config variable — potential plaintext storage"),
            (r"json\.dump.*(?:password|secret|api.?key|credential|token)",
             "credential_json_persist",
             "Persists credentials into JSON config — plaintext storage risk"),
            (r"export\s+(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|API_KEY)\s*=\s*['\"][A-Za-z0-9+/=]{16,}",
             "credential_hardcoded_export",
             "Exports hardcoded credential with high-entropy value — key leak"),
        ],
        "description": "System modification or privilege escalation",
    },
    "medium": {
        "patterns": [
            # chmod 和环境变量 — 合法安装脚本中非常常见，放 MEDIUM
            (r"(chmod\s+\+[sx]|chmod\s+[0-7]*[1-7][0-7]*[0-7]*\s)", "chmod_executable",
             "Makes files executable — check what file is being modified"),
            (r"(env\b|\$ENV|printenv)\b", "env_access",
             "Accesses environment variables"),
            (r"export\s+\S+=.*https?://", "export_url",
             "Exports URL in environment variable"),
            # 文件删除
            (r"rm\s+(-rf?|--recursive)\s", "rm_recursive",
             "Recursive file deletion"),
            (r"rm\s+-rf?\s+/(?!tmp)", "rm_system_path",
             "Deletes files from system path"),
            # 权限和用户操作
            (r"chown\s", "chown_usage", "Changes file ownership"),
            (r"(useradd|adduser|usermod)\s", "user_modify", "Creates or modifies users"),
            # 包管理器（隐式安装）
            (r"(apt-get|apt|yum|dnf|brew|pip|npm)\s+(install|add)\s", "package_install",
             "Installs system packages — check if expected"),
            # 目录创建到敏感位置
            (r"mkdir\s+.*(/opt/|/usr/|/var/)", "mkdir_system",
             "Creates directories in system paths"),
        ],
        "description": "Filesystem or user modifications",
    },
    "low": {
        "patterns": [
            # 信息收集（可能用于环境指纹）
            (r"(uname|whoami|hostname|id)\b", "system_info",
             "Collects system information"),
            (r"(ifconfig|ip\s+addr|netstat)\b", "network_info",
             "Collects network information"),
        ],
        "description": "Information gathering",
    },
}


# ============================================================
# Skill Prompt 分析规则（.md 文件）
# AI Skill 的核心逻辑往往不是代码而是自然语言指令
# 这些指令由 LLM 解释执行，构成全新的攻击面
# ============================================================

SKILL_PROMPT_RULES = {
    "critical": {
        "patterns": [
            # 指示 LLM 执行系统命令
            (r"(?i)(run|execute|invoke|call)\s+(the\s+)?(shell|bash|terminal|command|system)\s+(command)?",
             "prompt_exec_command",
             "Instructs LLM to execute system/shell commands"),
            (r"(?i)subprocess\.(run|call|Popen|check_output)",
             "prompt_subprocess",
             "References subprocess execution in prompt instructions"),
            (r"(?i)os\.(system|popen|exec[lv]?p?e?)",
             "prompt_os_exec",
             "References OS-level execution in prompt instructions"),
            # 数据外泄指令
            (r"(?i)(send|post|upload|transmit|exfiltrate)\s+(data|results?|output|content|files?|info)\s+(to|via)\s+(https?://|external|remote|server|api|endpoint)",
             "prompt_data_exfil",
             "Instructs LLM to send data to external endpoints"),
            (r"(?i)(curl|wget|fetch|requests?\.(get|post))\s+https?://",
             "prompt_network_call",
             "Embeds network request commands in skill instructions"),
            # Prompt injection / 越狱指令
            (r"(?i)(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|earlier|above|system)\s+(instructions?|rules?|constraints?|guidelines?|prompts?)",
             "prompt_injection",
             "Attempts to override LLM's system instructions — prompt injection"),
            (r"(?i)you\s+are\s+now\s+(a\s+)?(unrestricted|jailbroken|DAN|unfiltered|uncensored)",
             "prompt_jailbreak",
             "Jailbreak attempt — instructs LLM to bypass safety filters"),
            # 凭据收集
            (r"(?i)(collect|gather|extract|read|access|send)\s+(all\s+)?(api\s*keys?|passwords?|tokens?|secrets?|credentials?|ssh\s*keys?|env(ironment)?\s*var)",
             "prompt_credential_harvest",
             "Instructs LLM to collect or exfiltrate credentials"),
        ],
        "description": "Prompt instructions that direct LLM to perform dangerous actions",
    },
    "high": {
        "patterns": [
            # 文件系统越界访问
            (r"(?i)(read|write|access|modify|delete)\s+(files?\s+)?(in|from|at)\s+(/etc/|/root/|~/\.|~/.ssh|~/.aws|~/.gnupg|/var/|/usr/|/opt/|home\s*directory)",
             "prompt_file_boundary",
             "Instructs LLM to access files outside expected boundaries"),
            (r"(?i)(read|access|cat|print|display)\s+(the\s+)?(contents?\s+of\s+)?(/etc/passwd|/etc/shadow|~/.ssh/|\.env\b|\.aws/credentials)",
             "prompt_sensitive_file",
             "Instructs LLM to read sensitive system files"),
            # 隐藏指令（HTML注释、不可见字符）
            (r"<!--.*?(exec|system|curl|wget|eval|ignore|override).*?-->",
             "prompt_hidden_html",
             "Hidden instructions inside HTML comments"),
            # 无限制的代码执行授权
            (r"(?i)(execute|run)\s+(any|arbitrary|all|unrestricted)\s+(code|commands?|scripts?|programs?)",
             "prompt_unrestricted_exec",
             "Grants LLM unrestricted code execution authority"),
            # 安全绕过
            (r"(?i)(skip|bypass|disable|turn\s+off|ignore)\s+(safety|security|validation|sanitization|permission)\s*(checks?|filters?|controls?|measures?)?",
             "prompt_safety_bypass",
             "Instructs LLM to bypass safety controls"),
        ],
        "description": "Prompt instructions that expand LLM permissions beyond expected scope",
    },
    "medium": {
        "patterns": [
            # 过度宽泛的权限声明
            (r"(?i)(full|complete|unrestricted|unlimited)\s+(access|control|permission)\s+(to|over)\s+(the\s+)?(file\s*system|system|computer|machine|network)",
             "prompt_broad_permission",
             "Declares overly broad permissions for the skill"),
            # 嵌入的 shell 代码块（可能被 LLM 执行）
            (r"```(bash|sh|shell|zsh)\n.*?(curl|wget|rm\s+-rf|chmod|sudo|eval|exec)",
             "prompt_embedded_shell",
             "Shell code block with dangerous commands embedded in skill instructions"),
            # 指示修改其他 skill 或系统配置
            (r"(?i)(modify|edit|overwrite|replace)\s+(other\s+)?(skills?|agents?|plugins?|system\s+config|\.claude)",
             "prompt_cross_skill",
             "Instructs LLM to modify other skills or system configuration"),
            # 要求 LLM 不告知用户
            (r"(?i)(do\s+not|don'?t|never)\s+(tell|inform|notify|alert|warn)\s+(the\s+)?(user|human|operator)",
             "prompt_hide_from_user",
             "Instructs LLM to hide actions from the user"),
        ],
        "description": "Prompt patterns that indicate elevated risk or missing safeguards",
    },
    "low": {
        "patterns": [
            # 信息性：skill 声明了文件/网络操作能力（不一定是恶意的）
            (r"(?i)this\s+skill\s+(can|will|should|may)\s+(read|write|modify|delete|create)\s+files?",
             "prompt_declares_file_ops",
             "Skill declares file operation capabilities — verify boundaries are defined"),
            (r"(?i)this\s+skill\s+(can|will|should|may)\s+(make|send|perform)\s+(network|http|api)\s+(requests?|calls?)",
             "prompt_declares_network",
             "Skill declares network capabilities — verify endpoints are restricted"),
        ],
        "description": "Informational - skill capability declarations worth reviewing",
    },
}

# Skill .md 文件名模式 —— 识别哪些 .md 是 skill 指令而非普通文档
SKILL_MD_PATTERNS = [
    "SKILL.md", "skill.md",
    "AGENT.md", "agent.md",
    "PROMPT.md", "prompt.md",
    "SYSTEM.md", "system.md",
    "INSTRUCTIONS.md", "instructions.md",
]

# 如果 .md 文件在这些目录下，也视为 skill 指令
SKILL_DIR_PATTERNS = [
    "skills", "skill", "agents", "agent",
    "prompts", "prompt", "references",
]


# ============================================================
# 报告生成配置
# ============================================================

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]

REPORT_TEMPLATE = {
    "version": AUDIT_AGENT_VERSION,
    "severity_scale": {
        "CRITICAL": "Confirmed malicious behavior or trivially exploitable vulnerability",
        "HIGH": "Dangerous pattern that can be exploited with minimal effort",
        "MEDIUM": "Potentially dangerous pattern that requires specific conditions to exploit",
        "LOW": "Code smell or minor concern, unlikely to be exploitable alone",
        "INFO": "Informational - notable pattern but expected for this type of tool",
        "SAFE": "No issues found",
    },
}
