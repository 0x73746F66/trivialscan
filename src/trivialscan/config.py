import logging
from os.path import expanduser
from pathlib import Path
import yaml

__module__ = "trivialscan.config"

logger = logging.getLogger(__name__)


def get_config(filename: str = ".trivialscan-config.yaml") -> dict:
    rel_config = {}
    user_config = {}
    rel_config_path = Path(filename)
    user_config_path = Path(f"{expanduser('~')}/{filename}")
    if rel_config_path.is_file():
        rel_config = yaml.safe_load(rel_config_path.read_text(encoding="utf8"))
    if user_config_path.is_file():
        user_config = yaml.safe_load(user_config_path.read_text(encoding="utf8"))

    return {**user_config, **rel_config}


config = get_config()
