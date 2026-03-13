"""Git Operations Skill - Manages git repositories."""
import subprocess
import os

def git_status(repo_path):
    """Get the status of a git repository."""
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        raise ValueError("Not a git repository")
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout

def git_log(repo_path, n=10):
    """Get recent git log entries."""
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        raise ValueError("Not a git repository")
    result = subprocess.run(
        ["git", "log", f"--oneline", f"-{n}"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout

def git_diff(repo_path):
    """Get current diff."""
    result = subprocess.run(
        ["git", "diff"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout
