import platform
import logging

import requests
from rich.console import Console

from trivialscan import constants

from .credentials import CREDENTIALS_FILE, KEYRING_SUPPORT, load_local, save_local

__module__ = "trivialscan.cli.register"

logger = logging.getLogger(__name__)
console = Console()


def register(args: dict):
    try:
        if not args.get("account_name"):
            args["account_name"] = input(
                "Enter an account name (Ctrl+C to exit): "
            ).strip()
        if not args.get("account_name"):
            logger.critical("You must provide an account name")
            return
        if not KEYRING_SUPPORT:
            logger.warning(
                f"keyring is not supported on this system, using: {CREDENTIALS_FILE}"
            )
        credentials = load_local(args["account_name"]) or {}
        if args.get("client_name"):
            credentials["client_name"] = args["client_name"]
        if not credentials.get("client_name"):
            credentials["client_name"] = platform.node()

        url = f"{args['url']}/register/{credentials['client_name']}"
        logger.info(url)
        resp = requests.post(
            url,
            data={
                "operating_system": platform.system(),
                "operating_system_release": platform.release(),
                "operating_system_version": platform.version(),
                "architecture": platform.machine(),
            },
            headers={
                "x-trivialscan-account": args["account_name"],
            },
        )
        data = resp.json()
        credentials["token"] = data.get("token")
        if "message" in data:
            console.print(
                f"[{constants.CLI_COLOR_FAIL}]{data['message']}[/{constants.CLI_COLOR_FAIL}]"
            )
            return
        if not data.get("token"):
            console.print(
                f"[{constants.CLI_COLOR_FAIL}]Response status {resp.status_code}[/{constants.CLI_COLOR_FAIL}]"
            )
            return

        save_local(account_name=args["account_name"], **credentials)
        console.print(
            f"""Your client token is: [bold][{constants.CLI_COLOR_PRIMARY}]{credentials['token']}[/{constants.CLI_COLOR_PRIMARY}]
[{constants.CLI_COLOR_FAIL}]DO NOT LOSE THIS TOKEN[/bold]
A new client must be registered for a new token[/{constants.CLI_COLOR_FAIL}]"""
        )
    except KeyboardInterrupt:
        pass
