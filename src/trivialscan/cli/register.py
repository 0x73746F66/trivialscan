import platform
import logging
import json

import requests
from rich.console import Console
from rich.prompt import Prompt

from .. import constants, util
from .credentials import CREDENTIALS_FILE, KEYRING_SUPPORT, save_local

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

        request_url = f"{args['dashboard_api_url']}/claim/{cred_data['client_name']}"
        raw_body = json.dumps(
            {
                "operating_system": platform.system(),
                "operating_system_release": platform.release(),
                "operating_system_version": platform.version(),
                "architecture": platform.machine(),
            }
        )
        logger.debug(f"{request_url}\n{raw_body}")
        authorization_header = util.sign_request(
            cred_data["account_name"],
            args.get("api_key"),
            request_url,
            request_method="POST",
            raw_body=raw_body,
        )
        logger.debug(f"{request_url}\n{authorization_header}")
        resp = requests.post(
            request_url,
            data=raw_body,
            headers={
                "Content-Type": "application/json",
                "Authorization": authorization_header,
                "X-Trivialscan-Account": cred_data["account_name"],
                "X-Trivialscan-Version": args["cli_version"],
            },
            timeout=10,
        )
        if resp.status_code != 201:
            console.print(
                f"[{constants.CLI_COLOR_FAIL}]Response status {resp.status_code}[/{constants.CLI_COLOR_FAIL}]"
            )
            return
        data = resp.json()
        if not data.get("access_token"):
            console.print(
                f"[{constants.CLI_COLOR_FAIL}]Response status {resp.status_code}[/{constants.CLI_COLOR_FAIL}]"
            )
            return

        cred_data["token"] = data.get("access_token")
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
