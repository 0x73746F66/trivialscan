import logging
from os import path

import requests
from rich.console import Console
from rich.table import Table

from . import constants
from .credentials import load_credentials, CREDENTIALS_FILE, KEYRING_SUPPORT

__module__ = "trivialscan.cli.info"

logger = logging.getLogger(__name__)
console = Console()


def info(dashboard_api_url: str):
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
        table.add_column("Cloud Status", no_wrap=True)
        for account_name, conf in credentials.items():
            registration_status = "Unregistered"
            data = {}
            if account_name == "DEFAULT":
                continue
            if conf.get("client_name"):
                try:
                    resp = requests.get(
                        path.join(dashboard_api_url, "check-token"),
                        headers={
                            "x-trivialscan-account": account_name,
                            "x-trivialscan-client": conf["client_name"],
                            "x-trivialscan-token": conf.get("token"),
                        },
                    )
                    data = resp.json()
                except requests.exceptions.ConnectionError as err:
                    logger.exception(err)
                    console.print(
                        f"[{constants.CLI_COLOR_FAIL}]Unable to reach the Trivial Security servers[/{constants.CLI_COLOR_FAIL}]"
                    )
                    registration_status = "Offline"
                except requests.exceptions.JSONDecodeError:
                    logger.warning(
                        f"Bad response from server ({resp.status_code}): {resp.text}"
                    )
                    registration_status = "Offline"
            table.add_row(
                account_name,
                conf.get("client_name"),
                conf.get("token"),
                "Registered" if data.get("registered") else registration_status,
            )

        console.print(table)

    except KeyboardInterrupt:
        pass
