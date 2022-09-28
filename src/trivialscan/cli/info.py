import logging
from os import path

import requests
from rich.console import Console
from rich.table import Table

from .. import constants, util
from .credentials import (
    load_credentials,
    load_keyring,
    CREDENTIALS_FILE,
    KEYRING_SUPPORT,
)

__module__ = "trivialscan.cli.info"

logger = logging.getLogger(__name__)
console = Console()


def cloud_sync_status(
    dashboard_api_url: str,
    cli_version: str,
    account_name: str,
    registration_token: str,
    client_name: str = None,
) -> str:
    registration_status = (
        f"[{constants.CLI_COLOR_WARN}]Unregistered[/{constants.CLI_COLOR_WARN}]"
    )
    if not client_name:
        return registration_status
    data = {}
    request_url = path.join(dashboard_api_url, "check-token")
    authorization_header = util.sign_request(
        client_name, registration_token, request_url
    )
    logger.debug(authorization_header)
    try:
        resp = requests.get(
            request_url,
            headers={
                "Authorization": authorization_header,
                "X-Trivialscan-Account": account_name,
                "X-Trivialscan-Version": cli_version,
            },
            timeout=300,
        )
        data = resp.json()
    except requests.exceptions.ConnectionError as err:
        logger.exception(err)
        console.print(
            f"[{constants.CLI_COLOR_FAIL}]Unable to reach the Trivial Security servers[/{constants.CLI_COLOR_FAIL}]"
        )
        registration_status = (
            f"[{constants.CLI_COLOR_FAIL}]Offline[/{constants.CLI_COLOR_FAIL}]"
        )
    except requests.exceptions.JSONDecodeError:
        logger.warning(f"Bad response from server ({resp.status_code}): {resp.text}")
        registration_status = (
            f"[{constants.CLI_COLOR_FAIL}]Offline[/{constants.CLI_COLOR_FAIL}]"
        )
    data["registration_result"] = (
        f"[{constants.CLI_COLOR_PASS}]Registered[/{constants.CLI_COLOR_PASS}]"
        if data.get("registered")
        else registration_status
    )
    return data


def info(dashboard_api_url: str, cli_version: str):
    logger.info(f"dashboard_api_url {dashboard_api_url}")
    try:
        if KEYRING_SUPPORT:
            console.print(
                f"[{constants.CLI_COLOR_PASS}]PASS![/{constants.CLI_COLOR_PASS}] keyring support"
            )
        else:
            console.print(
                f"[{constants.CLI_COLOR_WARN}]WARN![/{constants.CLI_COLOR_WARN}] keyring is not supported on this system"
            )
        credentials = load_credentials() or {}
        if not credentials:
            console.print(
                f"Credentials file {CREDENTIALS_FILE} not present on this system"
            )
            return

        console.print(
            f"[{constants.CLI_COLOR_INFO}]FOUND[/{constants.CLI_COLOR_INFO}] {CREDENTIALS_FILE}"
        )
        table = Table()
        table.add_column(
            "Account", justify="right", style=constants.CLI_COLOR_PRIMARY, no_wrap=True
        )
        table.add_column(
            "Client", justify="right", style=constants.CLI_COLOR_INFO, no_wrap=True
        )
        table.add_column("Registration Token", style="bold", no_wrap=True)
        table.add_column("Credential Storage", no_wrap=True)
        table.add_column("Cloud Status", no_wrap=True)
        table.add_column("Authorization Result", no_wrap=True)
        for account_name, conf in credentials.items():
            if conf.get("token"):
                console.print(
                    f"[{constants.CLI_COLOR_WARN}]WARN![/{constants.CLI_COLOR_WARN}] Registration token is stored as cleartext"
                )
            registration_token = load_keyring(account_name, conf.get("client_name"))
            if registration_token:
                console.print(
                    f"[{constants.CLI_COLOR_PASS}]PASS![/{constants.CLI_COLOR_PASS}] Retrieved registration token from keyring"
                )
                data = cloud_sync_status(
                    dashboard_api_url,
                    cli_version,
                    account_name,
                    registration_token,
                    conf.get("client_name"),
                )
                logger.debug(data)
                table.add_row(
                    account_name,
                    conf.get("client_name"),
                    registration_token,
                    f"[{constants.CLI_COLOR_PASS}]Encrypted Keyring[/{constants.CLI_COLOR_PASS}]",
                    data["registration_result"],
                    "Validated"
                    if data.get("authorisation_valid")
                    else data.get("authorisation_valid", "Missing") or "Unauthorized",
                )
            if (
                account_name == "DEFAULT"
                or not conf.get("token")
                or registration_token == conf.get("token")
            ):
                continue
            data = cloud_sync_status(
                dashboard_api_url,
                cli_version,
                account_name,
                conf.get("token"),
                conf.get("client_name"),
            )
            logger.debug(data)
            table.add_row(
                account_name,
                conf.get("client_name"),
                conf.get("token"),
                f"[{constants.CLI_COLOR_FAIL}]Cleartext File[/{constants.CLI_COLOR_FAIL}]",
                data["registration_result"],
                "Validated"
                if data.get("authorisation_valid")
                else data.get("authorisation_valid", "Missing") or "Unauthorized",
            )

        console.print(table)

    except KeyboardInterrupt:
        pass
