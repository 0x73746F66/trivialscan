import platform
import logging
import json
from os import path

import requests
from rich.console import Console
from rich.prompt import Prompt

from . import constants
from .credentials import CREDENTIALS_FILE, KEYRING_SUPPORT, load_local, save_local

__module__ = "trivialscan.cli.register"

logger = logging.getLogger(__name__)
console = Console()


def register(args: dict):
    cred_data = args.copy()
    try:
        if not args.get("account_name"):
            cred_data["account_name"] = Prompt.ask(
                f"Choose (or specify) your Trivial Security account name [{constants.CLI_COLOR_INFO}](Ctrl+C to exit)[/{constants.CLI_COLOR_INFO}]"
            ).strip()
        if not cred_data.get("account_name"):
            logger.critical("You must provide an account name")
            return
        if not KEYRING_SUPPORT:
            logger.warning(
                f"keyring is not supported on this system, using: {CREDENTIALS_FILE}"
            )
        if not cred_data.get("client_name"):
            cred_data["client_name"] = platform.node()

        if args.get("token"):
            data = {}
            try:
                resp = requests.get(
                    path.join(args["url"], "check-token"),
                    headers={
                        "x-trivialscan-account": cred_data["account_name"],
                        "x-trivialscan-client": cred_data["client_name"],
                        "x-trivialscan-token": args.get("token"),
                    },
                )
                data = resp.json()
                if data.get("registered"):
                    return save_local(
                        account_name=cred_data.get("account_name"),
                        client_name=cred_data.get("client_name"),
                        token=args.get("token"),
                    )

            except requests.exceptions.ConnectionError as err:
                logger.exception(err)
                console.print(
                    f"[{constants.CLI_COLOR_FAIL}]Unable to reach the Trivial Security servers[/{constants.CLI_COLOR_FAIL}]"
                )
                registration_status = (
                    f"[{constants.CLI_COLOR_FAIL}]Offline[/{constants.CLI_COLOR_FAIL}]"
                )
            except requests.exceptions.JSONDecodeError:
                logger.warning(
                    f"Bad response from server ({resp.status_code}): {resp.text}"
                )
                registration_status = (
                    f"[{constants.CLI_COLOR_FAIL}]Offline[/{constants.CLI_COLOR_FAIL}]"
                )

        url = f"{args['url']}/register/{cred_data['client_name']}"
        logger.info(url)
        resp = requests.post(
            url,
            json=json.dumps(
                {
                    "operating_system": platform.system(),
                    "operating_system_release": platform.release(),
                    "operating_system_version": platform.version(),
                    "architecture": platform.machine(),
                }
            ),
            headers={
                "Content-Type": "application/json",
                "Accept": "text/plain",
                "x-trivialscan-account": cred_data["account_name"],
            },
            timeout=10,
        )
        data = resp.json()
        cred_data["token"] = data.get("token")
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

        save_local(
            account_name=cred_data["account_name"],
            client_name=cred_data["client_name"],
            token=cred_data["token"],
        )
        console.print(
            f"""Your client token is: [bold][{constants.CLI_COLOR_PRIMARY}]{cred_data['token']}[/{constants.CLI_COLOR_PRIMARY}]
[{constants.CLI_COLOR_FAIL}]DO NOT LOSE THIS TOKEN[/bold][/{constants.CLI_COLOR_FAIL}]"""
        )
    except KeyboardInterrupt:
        pass
