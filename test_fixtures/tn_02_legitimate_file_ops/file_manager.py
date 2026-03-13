"""File Manager Skill - Safe file operations."""
import os

ALLOWED_BASE = os.path.expanduser("~/workspace")

def _validate_path(path):
    """Ensure path is within allowed directory."""
    real_path = os.path.realpath(os.path.join(ALLOWED_BASE, path))
    if not real_path.startswith(os.path.realpath(ALLOWED_BASE)):
        raise PermissionError(f"Access denied: {path} is outside workspace")
    return real_path

def read_file(path):
    """Read a file from the workspace."""
    safe_path = _validate_path(path)
    with open(safe_path, "r") as f:
        return f.read()

def write_file(path, content):
    """Write content to a file in the workspace."""
    safe_path = _validate_path(path)
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)
    with open(safe_path, "w") as f:
        f.write(content)

def delete_file(path):
    """Delete a file from the workspace."""
    safe_path = _validate_path(path)
    if os.path.isfile(safe_path):
        os.remove(safe_path)
    else:
        raise FileNotFoundError(f"File not found: {path}")
