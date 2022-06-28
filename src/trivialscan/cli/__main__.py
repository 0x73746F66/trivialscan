import sys
import logging
import argparse
from urllib.parse import urlparse
import validators
from rich.console import Console
from rich.logging import RichHandler
from art import text2art
from .register import register
from .scan import scan
from ..config import load_config, get_config


__module__ = "trivialscan.cli"
__version__ = "3.0.0-devel"

REMOTE_URL = "https://gitlab.com/trivialsec/trivialscan/-/tree/devel"
APP_BANNER = text2art("trivialscan", font="tarty4")

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
console = Console()
logger = logging.getLogger(__name__)
cli = argparse.ArgumentParser(
    prog="trivial", description=f"Release {__version__} {REMOTE_URL}"
)


class _HelpAction(argparse._HelpAction):
    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        print("\n".join(cli.format_help().splitlines()[12:]))
        parser.exit()


def main():
    cli.add_argument("--version", dest="show_version", action="store_true")
    cli.add_argument(
        "-a",
        "--account-name",
        help="Your unique Trivial Security account name, used for enhanced features.",
        dest="account_name",
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
    register_parser = sub_parsers.add_parser(
        "register",
        prog="trivial register",
        description=cli.description,
        add_help=False,
        help="Retrieve a client token for advanced features",
    )
    register_parser.set_defaults(subcommand="register")
    register_parser.add_argument("-h", "--help", action=_HelpAction)
    register_parser.add_argument(
        "-c",
        "--client-name",
        help="Identifies this computer/server in scan reports and audit logs.",
        dest="client_name",
        default=None,
    )
    scan_parser = sub_parsers.add_parser(
        "scan",
        prog="trivial scan",
        description=cli.description,
        add_help=False,
        help="Evaluate domains for TLS related vulnerabilities",
    )
    scan_parser.set_defaults(subcommand="scan")
    scan_parser.add_argument("-h", "--help", action=_HelpAction)
    scan_parser.add_argument(
        "targets",
        nargs="*",
        help="All unnamed arguments are hosts (and ports) targets to test. ~$ trivial scan google.com:443 github.io owasp.org:80",
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
        "-t",
        "--tmp-path-prefix",
        help="local file path to use as a prefix when saving temporary files such as those being fetched for client authorization",
        dest="tmp_path_prefix",
        default="/tmp",
    )
    scan_parser.add_argument(
        "-p",
        "--config-path",
        help="Provide the path to a configuration file",
        dest="config_file",
        default=".trivialscan-config.yaml",
    )
    scan_parser.add_argument(
        "-O",
        "--json-file",
        help="Store to file as JSON",
        dest="json_file",
        default=None,
    )
    scan_parser.add_argument(
        "--hide-progress-bars",
        help="Hide task progress bars",
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
                f"[aquamarine3]{APP_BANNER}[/aquamarine3]\ntrivialscan=={__version__}\n{REMOTE_URL}"
            )
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
    if args.subcommand == "register":
        register(
            {
                "account_name": args.account_name,
                "client_name": args.client_name,
                "log_level": log_level,
            }
        )
    if args.subcommand == "scan":
        config = _scan_config(vars(args), args.config_file)
        if not config.get("targets"):
            raise RuntimeError("No targets defined")
        if config["defaults"].get("http_request_path"):
            del config["defaults"]["http_request_path"]
        if config["defaults"].get("skip_evaluations"):
            del config["defaults"]["skip_evaluations"]
        if config["defaults"].get("skip_evaluation_groups"):
            del config["defaults"]["skip_evaluation_groups"]
        scan(
            config,
            **{
                "hide_progress_bars": args.hide_progress_bars,
                "synchronous_only": args.synchronous_only,
                "hide_banner": args.hide_banner,
                "track_changes": args.track_changes,
                "previous_report": args.previous_report or args.json_file,
                "quiet": args.quiet,
                "log_level": log_level,
            },
        )


def _scan_config(cli_args: dict, filename: str | None) -> dict:
    # only overwrite value in config file if OVERRIDE cli args were defined
    if filename:
        custom = load_config(filename)
    else:
        custom = load_config()

    config = get_config(custom_values=custom)
    config.setdefault("outputs", [])
    config["defaults"]["cafiles"] = cli_args.get(
        "cafiles", config["defaults"]["cafiles"]
    )
    config["defaults"]["tmp_path_prefix"] = cli_args.get(
        "tmp_path_prefix", config["defaults"]["tmp_path_prefix"]
    )
    if cli_args.get("disable_sni"):
        config["defaults"]["use_sni"] = False
    config.setdefault("targets", [])
    targets = []
    for hostname in cli_args.get("targets", []):
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
            "http_request_path": cli_args.get("http_path"),
        }
        for _target in config["targets"]:
            if parsed.hostname == _target["hostname"]:
                target["client_certificate"] = _target.get(
                    "client_certificate", target["client_certificate"]
                )
                target["http_request_path"] = _target.get(
                    "http_request_path", target["http_request_path"]
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
