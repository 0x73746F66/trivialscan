import sys
import logging
from datetime import datetime
from os import path
from pathlib import Path
from urllib.parse import urlparse

import validators
import yaml
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm

from .. import cli, constants
from ..config import base_config, DEFAULT_CONFIG

__module__ = "trivialscan.cli.generate"

logger = logging.getLogger(__name__)
console = Console()
DEFAULT_PROJECT = f"trivialsec_{datetime.now().year}"


def _gather_target() -> tuple[str, int]:
    domain_name = Prompt.ask(
        f"Enter a domain name [{constants.CLI_COLOR_INFO}](Ctrl+C to exit)[/{constants.CLI_COLOR_INFO}]"
    ).strip()
    if not domain_name:
        console.print(
            f"[{constants.CLI_COLOR_FAIL}]No domain name supplied, exiting[/{constants.CLI_COLOR_FAIL}]"
        )
        sys.exit(0)
    if not domain_name.startswith("http"):
        domain_name = f"https://{domain_name}"
    parsed = urlparse(domain_name)
    if validators.domain(parsed.hostname) is not True:
        console.print(f"{domain_name} hostname {parsed.hostname} is invalid")
        sys.exit(0)

    port = IntPrompt.ask("Enter a port", default=443, show_default=True)
    return parsed.hostname, port


def generate(args: dict):
    try:
        conf = base_config()
        if args.get("account_name"):
            conf["account_name"] = args.get("account_name")
        else:
            conf["account_name"] = Prompt.ask(
                f"""Enter your Trivial Security account name.
[bold]Tip[/bold]: You set the account name when you run the command; "[{constants.CLI_COLOR_PRIMARY}]trivial register[/{constants.CLI_COLOR_PRIMARY}]"
Enter anything here for local only use [{constants.CLI_COLOR_INFO}](Ctrl+C to exit)[/{constants.CLI_COLOR_INFO}]"""
            ).strip()
        if not conf.get("account_name"):
            console.print(
                f"[{constants.CLI_COLOR_FAIL}]No account name provided, aborting[/{constants.CLI_COLOR_FAIL}]"
            )
            sys.exit(1)
        if not args.get("project_name"):
            conf["project_name"] = Prompt.ask(
                f"Enter a project name [{constants.CLI_COLOR_INFO}](Ctrl+C to exit)[/{constants.CLI_COLOR_INFO}]",
                default=DEFAULT_PROJECT,
                show_default=True,
            ).strip()
        if not conf.get("project_name"):
            console.print(f"Using default project name '{DEFAULT_PROJECT}'")
            conf["project_name"] = DEFAULT_PROJECT

        targets = []
        while adding_domains := Confirm.ask(
            "Do you want add a target domain?", default=True
        ):
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
        if config_file.is_file() and not Confirm.ask(
            f"Do you want to over write {conf_path}?", default=True
        ):
            custom_file = Prompt.ask(
                "Enter a file name: ", default=DEFAULT_CONFIG
            ).strip()
            if not custom_file:
                console.print(
                    f"[{constants.CLI_COLOR_FAIL}]No file name supplied, exiting[/{constants.CLI_COLOR_FAIL}]"
                )
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
