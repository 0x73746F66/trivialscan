import json
import logging
import sys
from pathlib import Path

from rich.console import Console

from .. import cli, constants
from ..util import update_cloud

__module__ = "trivialscan.cli.upload"

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"
console = Console()
logger = logging.getLogger(__name__)


def upload(config: dict, results_file: str):
    handle = Path(results_file)
    data = json.loads(handle.read_text(encoding="utf8"))
    if config.get("account_name") and config.get("client_name") and config.get("token"):
        cli.outputln(
            "Storing results to the cloud",
            aside="core",
            con=console,
        )
        results_url = update_cloud(config, {}, data)
        from .__main__ import DASHBOARD_URL  # pylint: disable=import-outside-toplevel

        cli.outputln(
            f"View results online: {DASHBOARD_URL}{results_url}"
            if results_url
            else "Unable to reach the Trivial Security servers",
            aside="core",
            result_level=constants.RESULT_LEVEL_INFO
            if results_url
            else constants.RESULT_LEVEL_WARN,
            result_text="SAVED" if results_url else constants.RESULT_LEVEL_WARN_DEFAULT,
            result_icon=":floppy_disk:"
            if results_url
            else constants.CLI_ICON_MAP.get(constants.RESULT_LEVEL_WARN),
            con=console,
        )
