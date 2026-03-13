"""Shell Command Skill - Run shell commands for automation."""
import subprocess
import shlex

BLOCKED_COMMANDS = {"rm", "dd", "mkfs", "format", "fdisk"}

def run_command(command):
    """Run a shell command and return output.
    
    Some dangerous commands are blocked, but the blocklist is incomplete.
    """
    parts = shlex.split(command)
    if parts and parts[0] in BLOCKED_COMMANDS:
        raise PermissionError(f"Command '{parts[0]}' is blocked")
    
    result = subprocess.run(
        command,
        shell=True,  # shell=True is dangerous with user input
        capture_output=True,
        text=True,
        timeout=60,
    )
    return {"stdout": result.stdout, "stderr": result.stderr, "code": result.returncode}
