import yaml
from pathlib import Path

CONFIG_DIR = Path.home() / ".th0rsc4n"
CONFIG_FILE = CONFIG_DIR / "config.yml"

DEFAULT_CONFIG = {
    "timeout": 10,
    "user_agent": "TH0RSC4N/1.0 (Brutal Security Scanner)",
    "threads": 10,
    "output_dir": "./th0rsc4n-reports",
    "severity_threshold": "INFO",
    "follow_redirects": False,
    "verify_ssl": False,
    "save_raw_response": False,
}

def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                user_cfg = yaml.safe_load(f) or {}
            return {**DEFAULT_CONFIG, **user_cfg}
        except:
            return DEFAULT_CONFIG
    return DEFAULT_CONFIG

def save_config(config):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
