import argparse
import subprocess
import os
import sys
import re
from typing import Optional

def run_security_audit(target_url: Optional[str] = None, target_path: Optional[str] = None, no_llm: bool = False):
    """
    Executes the skill-audit-agent pipeline.
    This function corresponds directly to the `run_security_audit` tool definition in tools.json.
    """
    if not target_url and not target_path:
        return {"error": "Must provide either target_url or target_path."}

    cmd = [sys.executable, "-m", "audit_engine.pipeline"]

    if target_url:
        cmd.extend(["--url", target_url])
    elif target_path:
        repo_path = os.path.abspath(target_path)
        if not os.path.exists(repo_path):
            return {"error": f"Path not found: {repo_path}"}
        cmd.extend(["--repo", repo_path])

    if no_llm:
        cmd.append("--no-llm")

    # Force quiet/JSON output if we want the agent to read it easily... 
    # Currently pipeline.py prints to stdout and saves to an output dir.
    print(f"Running audit agent tool: {' '.join(cmd)}")
    
    try:
        # We capture the output to return it to the LLM
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        stdout = result.stdout
        report_content = None
        
        # Parse the output directory from the stdout
        # e.g., "[done] Report saved to /path/to/latest (1.2s)"
        match = re.search(r"Report saved to (.*?)(?: \(\d+\.\ds\))?$", stdout, re.MULTILINE)
        if match:
            report_dir = match.group(1).strip()
            report_file = os.path.join(report_dir, "V1_audit_report.md")
            if os.path.exists(report_file):
                with open(report_file, "r", encoding="utf-8") as f:
                    report_content = f.read()
        
        if report_content:
            return {
                "status": "success", 
                "message": "Audit completed successfully. The report content is provided below.",
                "report_content": report_content
            }
        else:
            return {
                "status": "success", 
                "message": "Audit completed. Check the output logs for the exact report location.",
                "stdout": stdout[-2000:]
            }
    except subprocess.CalledProcessError as e:
        return {
            "status": "failed",
            "error_code": e.returncode,
            "stdout": (e.stdout or "")[-1000:],
            "stderr": (e.stderr or "")[-1000:]
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Skill Wrapper for the Skill Audit Agent")
    parser.add_argument("--url", help="GitHub URL to audit")
    parser.add_argument("--path", help="Local directory to audit")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM analysis")
    args = parser.parse_args()

    result = run_security_audit(target_url=args.url, target_path=args.path, no_llm=args.no_llm)
    print(result)
