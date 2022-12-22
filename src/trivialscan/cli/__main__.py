import sys
import logging
import argparse
from os import getenv
from urllib.parse import urlparse
from pathlib import Path
from typing import Union

import validators
from rich.console import Console
from rich.logging import RichHandler
from art import text2art

from . import outputln
from .register import register
from .generate import generate
from .info import info
from .auth import auth
from .scan import scan
from .. import constants, util
from ..config import load_config, get_config, DEFAULT_CONFIG
from .credentials import load_local

__module__ = "trivialscan.cli"
__version__ = "0.5.0"

REMOTE_URL = "https://gitlab.com/trivialsec/trivialscan/"
APP_BANNER = text2art("trivialscan", font="tarty4")
APP_ENV = getenv("APP_ENV", "production")
DASHBOARD_API_URL = getenv(
    "TRIVIALSCAN_API_URL",
    str(
        util.get_cname("dev-api.trivialsec.com")
        if APP_ENV == "development"
        else util.get_cname("prod-api.trivialsec.com")
    ),
).strip(".")
DASHBOARD_URL = getenv(
    "TRIVIALSCAN_DASHBOARD_URL",
    "https://dev.trivialsec.com"
    if APP_ENV == "development"
    else "https://www.trivialsec.com",
)

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"
console = Console()
logger = logging.getLogger(__name__)
cli = argparse.ArgumentParser(
    prog="trivial",
    description=f"Release {__version__} {REMOTE_URL}",
    add_help=False,
)


class _HelpAction(argparse._HelpAction):
    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        parser.exit()


def main():
    cli.add_argument("--version", dest="show_version", action="store_true")
    cli.add_argument(
        "-D",
        "--api-url",
        help="URL for the Trivial Scanner dashboard API endpoint",
        dest="dashboard_api_url",
        default=DASHBOARD_API_URL,
    )
    cli.add_argument(
        "-a",
        "--account-name",
        help="Your unique Trivial Security account name, used for enhanced features.",
        dest="account_name",
        default=None,
    )
    cli.add_argument(
        "-N",
        "--client-name",
        help="Identifies this computer/server in scan reports and audit logs.",
        dest="client_name",
        default=None,
    )
    cli.add_argument(
        "-q",
        "--quiet",
        help="show no stdout (useful in automation when producing structured data outputs)",
        dest="quiet",
        action="store_true",
    )
    cli.add_argument("--no-banner", dest="hide_banner", action="store_true")
    group = cli.add_mutually_exclusive_group()
    group.add_argument(
        "-v",
        "--errors-only",
        help="set logging level to ERROR (default CRITICAL)",
        dest="log_level_error",
        action="store_true",
    )
    group.add_argument(
        "-vv",
        "--warning",
        help="set logging level to WARNING (default CRITICAL)",
        dest="log_level_warning",
        action="store_true",
    )
    group.add_argument(
        "-vvv",
        "--info",
        help="set logging level to INFO (default CRITICAL)",
        dest="log_level_info",
        action="store_true",
    )
    group.add_argument(
        "-vvvv",
        "--debug",
        help="set logging level to DEBUG (default CRITICAL)",
        dest="log_level_debug",
        action="store_true",
    )
    sub_parsers = cli.add_subparsers()
    generate_parser = sub_parsers.add_parser(
        "generate",
        prog="trivial generate",
        description=cli.description,
        add_help=False,
        help="Generate a basic configuration file",
        parents=[cli],
    )
    generate_parser.set_defaults(subcommand="generate")
    generate_parser.add_argument("-h", "--help", action=_HelpAction)
    info_parser = sub_parsers.add_parser(
        "info",
        prog="trivial info",
        description=cli.description,
        add_help=False,
        help="Show cli related information for this client",
        parents=[cli],
    )
    info_parser.set_defaults(subcommand="info")
    info_parser.add_argument("-h", "--help", action=_HelpAction)
    register_parser = sub_parsers.add_parser(
        "register",
        prog="trivial register",
        description=cli.description,
        add_help=False,
        help="Retrieve a client token for advanced features",
        parents=[cli],
    )
    register_parser.set_defaults(subcommand="register")
    register_parser.add_argument("-h", "--help", action=_HelpAction)
    register_parser.add_argument(
        "--api-key",
        dest="api_key",
        help="Requires registration at https://www.trivialsec.com",
    )
    auth_parser = sub_parsers.add_parser(
        "auth",
        prog="trivial auth",
        description=cli.description,
        add_help=False,
        help="Authenticate a client access token for advanced features",
        parents=[cli],
    )
    auth_parser.set_defaults(subcommand="auth")
    auth_parser.add_argument("-h", "--help", action=_HelpAction)
    auth_parser.add_argument(
        "--token",
        "--access-token",
        dest="access_token",
        help="Requires registration at https://www.trivialsec.com",
    )
    scan_parser = sub_parsers.add_parser(
        "scan",
        prog="trivial scan",
        description=cli.description,
        add_help=False,
        help="Evaluate domains for TLS related vulnerabilities",
        parents=[cli],
    )
    scan_parser.set_defaults(subcommand="scan")
    scan_parser.add_argument("-h", "--help", action=_HelpAction)
    scan_parser.add_argument(
        "--token",
        dest="token",
        default=None,
        help="Registration Token for the Trivial Scanner dashboard API",
    )
    scan_parser.add_argument(
        "-t",
        "--targets",
        dest="targets",
        nargs="*",
        help="All unnamed arguments are hosts (and ports) targets to test. ~$ trivial scan google.com:443 github.io owasp.org:80",
    )
    scan_parser.add_argument(
        "-P",
        "--project-name",
        help="",
        dest="project_name",
    )
    scan_parser.add_argument(
        "-c",
        "--cafiles",
        help="path to PEM encoded CA bundle file, url or file path accepted",
        dest="cafiles",
        default=None,
    )
    scan_parser.add_argument(
        "-C",
        "--client-pem",
        help="path to PEM encoded client certificate, url or file path accepted",
        dest="client_pem",
        default=None,
    )
    scan_parser.add_argument(
        "-H",
        "--http-path",
        help="path us use when testing HTTP requests, for headers and vulnerabilities. Defaulsts to '/'",
        dest="http_path",
        default="/",
    )
    scan_parser.add_argument(
        "-T",
        "--tmp-path-prefix",
        help="local file path to use as a prefix when saving temporary files such as those being fetched for client authorization",
        dest="tmp_path_prefix",
        default="/tmp",
    )
    scan_parser.add_argument(
        "-p",
        "--config-path",
        help=f"Provide the path to a configuration file (Default: {DEFAULT_CONFIG})",
        dest="config_file",
        default=DEFAULT_CONFIG,
    )
    scan_parser.add_argument(
        "-O",
        "--json-file",
        help="Store to file as JSON",
        dest="json_file",
        default=None,
    )
    scan_parser.add_argument(
        "--no-progress",
        help="Hide task progress bars, you can still press <left shift> to output progress stats",
        dest="hide_progress_bars",
        action="store_true",
    )
    scan_parser.add_argument(
        "--disable-sni",
        help="Do not negotiate SNI using INDA encoded host",
        dest="disable_sni",
        action="store_true",
    )
    scan_parser.add_argument(
        "--no-multiprocessing", dest="synchronous_only", action="store_true"
    )
    scan_parser.add_argument(
        "--track-changes", dest="track_changes", action="store_true"
    )
    scan_parser.add_argument(
        "--resume-checkpoint", dest="resume_checkpoint", action="store_true"
    )
    scan_parser.add_argument(
        "--hide-probe-info", dest="hide_probing", action="store_true"
    )
    scan_parser.add_argument(
        "--last-json",
        help="Stored JSON file to be used as baseline for --track-changes (Defaults to value of --json-file)",
        dest="previous_report",
        default=None,
    )
    args = cli.parse_args()
    if args.show_version:
        if args.hide_banner:
            console.print(f"trivialscan=={__version__}\n{REMOTE_URL}")
        else:
            console.print(
                f"[bold][{constants.CLI_COLOR_PRIMARY}]{APP_BANNER}[/{constants.CLI_COLOR_PRIMARY}][/bold]\ntrivialscan=={__version__}\n{REMOTE_URL}"
            )
        sys.exit(0)

    try:
        logger.info(f"subcommand {args.subcommand}")
    except AttributeError:
        cli.print_help()
        sys.exit(0)

    log_level = logging.CRITICAL
    if args.log_level_error:
        log_level = logging.ERROR
    if args.log_level_warning:
        log_level = logging.WARNING
    if args.log_level_info:
        log_level = logging.INFO
    if args.log_level_debug:
        log_level = logging.DEBUG

    handlers = []
    log_format = "%(asctime)s - %(name)s - [%(levelname)s] %(message)s"
    if not args.quiet and sys.stdout.isatty():
        log_format = "%(message)s"
        handlers.append(RichHandler(rich_tracebacks=True))
    logging.basicConfig(format=log_format, level=log_level, handlers=handlers)

    if args.subcommand == "generate":
        return generate({**vars(args)})

    if not args.dashboard_api_url or validators.url(args.dashboard_api_url) is not True:
        console.print(
            f"[{constants.CLI_COLOR_FAIL}]Missing or invalid value supplied for argument[/{constants.CLI_COLOR_FAIL}] -D|--api-url {args.dashboard_api_url}"
        )
        return

    if args.subcommand == "info":
        return info(
            dashboard_api_url=args.dashboard_api_url.strip("/"),
            cli_version=__version__,
        )
    if args.subcommand == "auth":
        return auth(
            {
                "account_name": args.account_name,
                "client_name": args.client_name,
                "access_token": args.access_token,
                "log_level": log_level,
                "dashboard_api_url": args.dashboard_api_url.strip("/"),
                "cli_version": __version__,
            }
        )
    if args.subcommand == "register":
        return register(
            {
                "account_name": args.account_name,
                "client_name": args.client_name,
                "api_key": args.api_key,
                "log_level": log_level,
                "dashboard_api_url": args.dashboard_api_url.strip("/"),
                "cli_version": __version__,
            }
        )
    config = _scan_config(vars(args), args.config_file)
    if args.subcommand == "scan":
        if not config.get("targets"):
            raise RuntimeError("No targets defined")
        if config["defaults"].get("http_request_path"):
            del config["defaults"]["http_request_path"]
        if config["defaults"].get("skip_evaluations"):
            del config["defaults"]["skip_evaluations"]
        if config["defaults"].get("skip_evaluation_groups"):
            del config["defaults"]["skip_evaluation_groups"]
        hide_banner = True if args.quiet else args.hide_banner
        use_console = (
            any(n.get("type") == "console" for n in config.get("outputs", []))
            and not args.quiet
        )
        use_icons = any(
            n.get("type") == "console" and n.get("use_icons")
            for n in config.get("outputs", [])
        )
        if use_console and not hide_banner:
            console.print(
                f"[bold][{constants.CLI_COLOR_PRIMARY}]{APP_BANNER}[/{constants.CLI_COLOR_PRIMARY}][/bold]"
            )
            console.print(
                f"{__version__}\t\t[bold][{constants.CLI_COLOR_PASS}]SUCCESS[/{constants.CLI_COLOR_PASS}] [{constants.CLI_COLOR_WARN}]ISSUE[/{constants.CLI_COLOR_WARN}] [{constants.CLI_COLOR_FAIL}]VULNERABLE[/{constants.CLI_COLOR_FAIL}] [{constants.CLI_COLOR_INFO}]INFO[/{constants.CLI_COLOR_INFO}] [{constants.CLI_COLOR_PRIMARY}]RESULT[/{constants.CLI_COLOR_PRIMARY}][/bold]"
            )
        if Path(args.config_file).is_file():
            outputln(
                args.config_file,
                aside="core",
                result_text="CONFIG",
                result_icon=":file_folder:",
                con=console if use_console else None,
                use_icons=use_icons,
            )
        return scan(
            config,
            **{
                "hide_progress_bars": args.hide_progress_bars,
                "synchronous_only": args.synchronous_only,
                "hide_banner": args.hide_banner,
                "track_changes": args.track_changes,
                "previous_report": args.previous_report or args.json_file,
                "quiet": args.quiet,
            },
        )


def _scan_config(cli_args: dict, filename: Union[str, None]) -> dict:
    custom = load_config(filename)
    config = get_config(custom_values=custom)
    config.setdefault("cli_version", __version__)
    config.setdefault(
        "dashboard_api_url", cli_args.get("dashboard_api_url", "").strip("/")
    )
    if cli_args.get("account_name"):
        config["account_name"] = cli_args.get("account_name")
    if cli_args.get("client_name"):
        config["client_name"] = cli_args.get("client_name")
    if cli_args.get("project_name"):
        config["project_name"] = cli_args.get("project_name")
    if cli_args.get("token"):
        config["token"] = cli_args.get("token")
    elif config.get("account_name") and config.get("client_name"):
        creds = load_local(config["account_name"], config["client_name"])
        config["token"] = creds.get("token")
    config.setdefault("outputs", [])
    config["defaults"]["cafiles"] = cli_args.get(
        "cafiles", config["defaults"]["cafiles"]
    )
    config["defaults"]["tmp_path_prefix"] = cli_args.get(
        "tmp_path_prefix", config["defaults"]["tmp_path_prefix"]
    )
    if cli_args.get("hide_probing", False):
        config["defaults"]["hide_probe_info"] = True
    if cli_args.get("resume_checkpoint", False):
        config["defaults"]["resume_checkpoint"] = True
    if cli_args.get("disable_sni"):
        config["defaults"]["use_sni"] = False
    config.setdefault("targets", [])
    targets = []
    for hostname in cli_args.get("targets", []) or []:
        if not hostname.startswith("http"):
            hostname = f"https://{hostname}"
        parsed = urlparse(hostname)
        if validators.domain(parsed.hostname) is not True:
            raise AttributeError(
                f"URL {hostname} hostname {parsed.hostname} is invalid"
            )
        target = {
            "hostname": parsed.hostname,
            "port": 443 if not parsed.port else parsed.port,
            "client_certificate": cli_args.get("client_pem"),
            "http_request_paths": [cli_args.get("http_path", "/")],
        }
        for _target in config["targets"]:
            if parsed.hostname == _target["hostname"]:
                if not cli_args.get("client_pem"):
                    target["client_certificate"] = _target.get("client_certificate")
                target["http_request_paths"] = _target.get(
                    "http_request_paths", cli_args.get("http_path")
                )
                target["skip_evaluations"] = _target.get("skip_evaluations", [])
                target["skip_evaluation_groups"] = _target.get(
                    "skip_evaluation_groups", []
                )
                break
        targets.append(target)
    if targets:
        config["targets"] = targets
    if cli_args.get("log_level_error"):
        config["outputs"] = [
            n for n in config.get("outputs", []) if n.get("type") != "console"
        ]
    if cli_args.get("json_file"):
        if any(n.get("type") == "json" for n in config.get("outputs", [])):
            config["outputs"] = [
                n for n in config.get("outputs", []) if n.get("type") != "json"
            ]
        config["outputs"].append({"type": "json", "path": cli_args.get("json_file")})

    return config


if __name__ == "__main__":
    main()
