import sys
import logging
from datetime import datetime
from os import path
from pathlib import Path
from urllib.parse import urlparse

import validators
import yaml
from rich.console import Console

from .. import cli
from ..config import base_config, ask, DEFAULT_CONFIG

__module__ = "trivialscan.cli.generate"

logger = logging.getLogger(__name__)
console = Console()
DEFAULT_PROJECT = f"trivialsec_{datetime.now().year}"


def _gather_target() -> tuple[str, int]:
    domain_name = input("Enter a domain name (Ctrl+C to exit): ").strip()
    if not domain_name:
        console.print("No domain name supplied, exiting")
        sys.exit(0)
    if not domain_name.startswith("http"):
        domain_name = f"https://{domain_name}"
    parsed = urlparse(domain_name)
    if validators.domain(parsed.hostname) is not True:
        console.print(f"{domain_name} hostname {parsed.hostname} is invalid")
        sys.exit(0)

    port = input("Enter a port (default: 443): ").strip()
    return parsed.hostname, int(port) if port else None


def generate(args: dict):
    try:
        conf = base_config()
        if not args.get("project_name"):
            conf["project_name"] = input(
                "Enter a project name (Ctrl+C to exit): "
            ).strip()
        if not conf.get("project_name"):
            console.print(f"Using default project name '{DEFAULT_PROJECT}'")
            conf["project_name"] = DEFAULT_PROJECT

        targets = []
        adding_domains = True
        while adding_domains:
            adding_domains = ask("Do you want add a target domain?")
            if not adding_domains:
                break
            domain, port = _gather_target()
            target = {}
            target["hostname"] = domain
            if port and port != 443:
                target["port"] = port
            targets.append(target)

        conf["outputs"] = [{"type": "console", "use_icons": True}]
        conf_path = DEFAULT_CONFIG
        conf["targets"] = targets
        config_file = Path(conf_path)
        if config_file.is_file() and not ask(f"Do you want to over write {conf_path}?"):
            custom_file = input("Enter a file name: ").strip()
            if not custom_file:
                console.print("No file name supplied, exiting")
                sys.exit(0)
            conf_path = custom_file
            config_file = Path(custom_file)

        Path(str(Path(conf_path).parent)).mkdir(exist_ok=True)
        config_file.write_text(
            yaml.dump(conf, encoding="utf-8", default_flow_style=False).decode(),
            encoding="utf-8",
        )
        cli.outputln(
            conf_path,
            aside="core",
            result_text="SAVED",
            result_icon=":floppy_disk:",
            con=console,
        )
    except KeyboardInterrupt:
        pass
