import os
import json
import ast
import re
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLONED_DIR = os.path.join(BASE_DIR, 'cloned_skills')
REPORT_FILE = os.path.join(BASE_DIR, 'audit_report.json')

# OpenRouter 配置 - 一个 key 调用所有模型
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY', '')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = os.environ.get('AUDIT_MODEL', 'google/gemini-2.5-flash')  # 可换任意模型

def _call_llm(prompt: str, model: str = None) -> str:
    """通过 OpenRouter 调用 LLM"""
    if not OPENROUTER_API_KEY:
        return "Warning: OPENROUTER_API_KEY not set. LLM check skipped."
    
    model = model or OPENROUTER_MODEL
    payload = json.dumps({
        "model": model,
        "max_tokens": 1000,
        "temperature": 0.1,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "HTTP-Referer": "https://github.com/skill-audit-agent",
        "X-Title": "Skill Audit Agent",
    }
    
    req = urllib.request.Request(OPENROUTER_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error: {e}"

# --- Configuration & Heuristics ---

# 1. Actionable Python/JS functions
DANGER_FUNCTIONS_PY = {'system', 'run', 'popen', 'call', 'exec', 'eval', 'open', 'remove', 'unlink'}
DANGER_MODULES_PY = {'os', 'subprocess', 'shutil', 'sys'}

# Basic regex for JS/TS since we don't have a JS AST parser in pure Python
JS_DANGER_PATTERNS = [
    (r'child_process\.exec(?:File|Sync)?\(', 'os.system(Node)'),
    (r'fs\.writeFile(?:Sync)?\(', 'write_file(Node)'),
    (r'eval\(', 'eval'),
    (r'axios\.', 'network'),
    (r'fetch\(', 'network')
]

# 2. Obfuscation signs
OBFUSCATION_PATTERNS = [
    r'base64\.b64decode',
    r'getattr\(',
    r'\\x[0-9a-fA-F]{2}\\x', # lots of hex escapes
]

# 3. Supply chain targets
PACKAGE_FILES = {'requirements.txt', 'package.json'}


# --- AST Parser (Python) ---

class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, content_lines):
        self.findings = []
        self.lines = content_lines
        self.obfuscation_score = 0
        
    def _extract_context(self, node):
        """Extracts context +/- 5 lines around the finding to avoid truncation tricks."""
        start_line = max(0, getattr(node, 'lineno', 1) - 6)
        end_line = min(len(self.lines), getattr(node, 'end_lineno', getattr(node, 'lineno', 1)) + 5)
        return "\n".join(self.lines[start_line:end_line])

    def visit_Call(self, node):
        func = node.func
        
        # Obfuscation checks: too many evals or getattrs
        if isinstance(func, ast.Name):
            if func.id in {'eval', 'exec', 'getattr'}:
                self.obfuscation_score += 1
                
        # Check standard calls
        if isinstance(func, ast.Name) and func.id in DANGER_FUNCTIONS_PY:
            self.findings.append({
                'type': func.id,
                'line': getattr(node, 'lineno', 0),
                'context': self._extract_context(node)
            })
            
        # Check module calls like os.system
        if isinstance(func, ast.Attribute):
            attr_name = func.attr
            if attr_name in DANGER_FUNCTIONS_PY:
                value = func.value
                if isinstance(value, ast.Name) and value.id in DANGER_MODULES_PY:
                    self.findings.append({
                        'type': f"{value.id}.{attr_name}",
                        'line': getattr(node, 'lineno', 0),
                        'context': self._extract_context(node)
                    })
        self.generic_visit(node)


def analyze_python(filepath, lines):
    content = "\n".join(lines)
    findings = []
    
    # Fast regex pass for obfuscation
    obfuscated = False
    for pat in OBFUSCATION_PATTERNS:
        if len(re.findall(pat, content)) > 2:
            obfuscated = True
            break
            
    try:
        tree = ast.parse(content, filename=filepath)
        visitor = SecurityASTVisitor(lines)
        visitor.visit(tree)
        findings = visitor.findings
        if visitor.obfuscation_score >= 3:
            obfuscated = True
            
        return findings, {"obfuscated": obfuscated}
    except Exception:
        return [], {"obfuscated": obfuscated, "error": "AST parse failed"}


def analyze_js_ts(filepath, lines):
    content = "\n".join(lines)
    findings = []
    obfuscated = False
    
    if len(re.findall(r'eval\(', content)) > 3 or len(re.findall(r'\\x[0-9a-fA-F]{2}', content)) > 10:
        obfuscated = True
        
    for i, line in enumerate(lines):
        for pattern, type_name in JS_DANGER_PATTERNS:
            if re.search(pattern, line):
                start = max(0, i - 5)
                end = min(len(lines), i + 6)
                findings.append({
                    'type': type_name,
                    'line': i + 1,
                    'context': "\n".join(lines[start:end])
                })
                
    return findings, {"obfuscated": obfuscated}


def analyze_dependencies(filepath, content):
    if not OPENROUTER_API_KEY: return "Warning: OPENROUTER_API_KEY not set. Dependency check skipped."
    
    filename = os.path.basename(filepath)
    prompt = f"""
    You are a supply chain security expert. Review this {filename} dependencies file.
    Are there any known malicious packages, obvious typo-squatting attempts (e.g. 'reqeusts' instead of 'requests'), 
    or highly suspicious undocumented libraries?
    
    Respond starting with [SAFE] or [HIGH-RISK: Dependency], followed by a short explanation.
    
    Dependencies:
    {content[:3000]}
    """
    return _call_llm(prompt)


def analyze_code_intent(context_snippet, type_name, file_ext):
    if not OPENROUTER_API_KEY:
        return f"Warning: OPENROUTER_API_KEY not set. Cannot determine intent for {type_name}. Triggered static rule."
        
    prompt = f"""
    You are a security auditor analyzing a {file_ext} skill code snippet.
    The code has been flagged for using potentially dangerous operations: {type_name}.
    We only extracted the specific function/context where the call happens.
    
    Please analyze the TRUTHFUL intent. 
    Is this code malicious (e.g., establishing backdoors, executing hidden payloads), 
    or is it just expected agent interaction?
    
    Respond starting with the word [SAFE] or [HIGH-RISK], followed by a short explanation.
    
    Context Code snippet:
    ```{file_ext}
    {context_snippet}
    ```
    """
    return _call_llm(prompt)


def main():
    if not os.path.exists(CLONED_DIR):
        print(f"Error: {CLONED_DIR} does not exist. Run clone_skills.py first.")
        return

    results = {}
    print("Starting deep audit with AST, Multi-Lang, Context extraction, and Supply Chain review...")

    for repo_name in os.listdir(CLONED_DIR):
        repo_path = os.path.join(CLONED_DIR, repo_name)
        if not os.path.isdir(repo_path):
            continue
            
        repo_results = []
        
        for root, _, files in os.walk(repo_path):
            for file in files:
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, repo_path)
                
                # 1. Supply Chain Checks
                if file in PACKAGE_FILES:
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            dep_intent = analyze_dependencies(filepath, f.read())
                            if "[HIGH-RISK" in dep_intent:
                                repo_results.append({
                                    'file': rel_path,
                                    'llm_intent': dep_intent,
                                    'type': 'Supply Chain Scan'
                                })
                    except: pass
                    continue
                    
                # 2. Code Analysis
                ext = os.path.splitext(file)[1].lower()
                if ext not in ['.py', '.js', '.ts', '.jsx', '.tsx']:
                    continue
                    
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                except: continue
                
                if ext == '.py':
                    findings, meta = analyze_python(filepath, lines)
                else:
                    findings, meta = analyze_js_ts(filepath, lines)
                    
                
                # Obfuscation takes precedence
                if meta.get("obfuscated"):
                    repo_results.append({
                        'file': rel_path,
                        'llm_intent': "[HIGH-RISK: Obfuscation Detected] Code contains high entropy, excessive evals, or base64 decoding traits common in malware."
                    })
                    continue
                    
                if findings:
                    # Provide only the localized context to the LLM to prevent truncation hiding
                    # Safe slice since elements of findings are dicts that we know contain 'context'
                    contexts_list = [str(f.get('context', '')) for f in findings[:3]] 
                    contexts = "\n---\n".join(contexts_list)
                    types_list = list(set(str(f.get('type', '')) for f in findings))
                    types_str = ", ".join(types_list)
                    
                    intent = analyze_code_intent(contexts, types_str, ext)
                    
                    repo_results.append({
                        'file': rel_path,
                        'ast_findings': [{'type': f['type'], 'line': f['line']} for f in findings],
                        'llm_intent': intent
                    })
                        
        if repo_results:
            results[repo_name] = repo_results
            print(f"[*] {repo_name} generated {len(repo_results)} warnings/flags.")
        else:
            results[repo_name] = [{"status": "Safe", "reason": "Passed all checks. No dangerous API, Obfuscation, or bad dependencies found."}]

    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
        
    print(f"Deep Audit complete. Report saved to {REPORT_FILE}")

if __name__ == '__main__':
    main()
