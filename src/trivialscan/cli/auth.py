import platform
import logging
import json

import requests
from rich.console import Console
from rich.prompt import Prompt

from .. import constants, util
from .credentials import CREDENTIALS_FILE, KEYRING_SUPPORT, save_local

__module__ = "trivialscan.cli.auth"

logger = logging.getLogger(__name__)
console = Console()


def auth(args: dict):
    cred_data = args.copy()
    try:
        if not args.get("account_name"):
            cred_data["account_name"] = Prompt.ask(
                f"Specify your Trivial Security account name [{constants.CLI_COLOR_INFO}](Ctrl+C to exit)[/{constants.CLI_COLOR_INFO}]"
            ).strip()
        if not cred_data.get("account_name"):
            logger.critical("You must provide the account name")
            return
        if not args.get("client_name"):
            cred_data["client_name"] = Prompt.ask(
                f"Specify your client name, either generated with the Registration Token or chosen by you using `trivial register` [{constants.CLI_COLOR_INFO}](Ctrl+C to exit)[/{constants.CLI_COLOR_INFO}]"
            ).strip()
        if not cred_data.get("client_name"):
            logger.critical("You must provide the client name")
            return
        if not args.get("access_token"):
            cred_data["access_token"] = Prompt.ask(
                f"Specify your Trivial Security client Registration Token [{constants.CLI_COLOR_INFO}](Ctrl+C to exit)[/{constants.CLI_COLOR_INFO}]"
            ).strip()
        if not cred_data.get("access_token"):
            logger.critical("You must provide a client Registration Token")
            return
        if not KEYRING_SUPPORT:
            logger.warning(
                f"keyring is not supported on this system, using: {CREDENTIALS_FILE}"
            )

        request_url = f"{args['dashboard_api_url']}/auth/{cred_data['client_name']}"
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
            client_id=cred_data["client_name"],
            secret_key=cred_data.get("access_token"),
            request_url=request_url,
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
        if not data.get("authorisation_valid"):
            console.print(
                f"[{constants.CLI_COLOR_FAIL}]Response status {resp.status_code}[/{constants.CLI_COLOR_FAIL}]"
            )
            return

        save_local(
            account_name=cred_data["account_name"],
            client_name=cred_data["client_name"],
            token=cred_data["access_token"],
        )
        console.print(
            f"[{constants.CLI_COLOR_PRIMARY}]Authenticated![/{constants.CLI_COLOR_PRIMARY}]"
        )
    except KeyboardInterrupt:
        pass
