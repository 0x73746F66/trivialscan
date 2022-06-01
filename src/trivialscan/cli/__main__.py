import sys
import logging
import argparse
import json
from multiprocessing import Pool, cpu_count, Queue
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import validators
import progressbar
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Column
from rich.progress import Progress, MofNCompleteColumn, TextColumn, SpinnerColumn
from trivialscan.transport.state import TransportState
from . import log
from .. import evaluate
from ..config import get_config

__module__ = "trivialscan.cli"
__version__ = "3.0.0-devel"
REMOTE_URL = "https://gitlab.com/trivialsec/trivialscan/-/tree/devel"

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
console = Console()
logger = logging.getLogger(__name__)

def no_progressbar(data: list):
    yield from data


def configure() -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "targets",
        nargs="*",
        help="All unnamed arguments are hosts (and ports) targets to test. ~$ trivialscan google.com:443 github.io owasp.org:80",
    )
    parser.add_argument(
        "-c",
        "--cafiles",
        help="path to PEM encoded CA bundle file, url or file path accepted",
        dest="cafiles",
        default=None,
    )
    parser.add_argument(
        "-C",
        "--client-pem",
        help="path to PEM encoded client certificate, url or file path accepted",
        dest="client_pem",
        default=None,
    )
    parser.add_argument(
        "-t",
        "--tmp-path-prefix",
        help="local file path to use as a prefix when saving temporary files such as those being fetched for client authorization",
        dest="tmp_path_prefix",
        default="/tmp",
    )
    parser.add_argument(
        "-p",
        "--config-path",
        help="Provide the path to a configuration file",
        dest="config_file",
        default=".trivialscan-config.yaml",
    )
    parser.add_argument(
        "-O",
        "--json-file",
        help="Store to file as JSON",
        dest="json_file",
        default=None,
    )
    parser.add_argument(
        "-q",
        "--hide-progress-bars",
        help="Hide task progress bars",
        dest="hide_progress_bars",
        action="store_true",
    )
    parser.add_argument(
        "--disable-sni",
        help="Do not negotiate SNI using INDA encoded host",
        dest="disable_sni",
        action="store_true",
    )
    parser.add_argument("--version", dest="show_version", action="store_true")
    group = parser.add_mutually_exclusive_group()
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
    args = parser.parse_args()
    if args.show_version:
        print(f"trivialscan=={__version__}\n{REMOTE_URL}")
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
    if sys.stdout.isatty():
        log_format = "%(message)s"
        handlers.append(RichHandler(rich_tracebacks=True))
    logging.basicConfig(format=log_format, level=log_level, handlers=handlers)
    progressbar.progressbar = no_progressbar

    base_config = get_config(args.config_file)
    return _cli_config(vars(args), base_config), args.hide_progress_bars


def _cli_config(cli_args: dict, config: dict) -> dict:
    # only overwrite value in config file if OVERRIDE cli args were defined
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
        targets.append(
            {
                "hostname": parsed.hostname,
                "port": 443 if not parsed.port else parsed.port,
                "client_certificate": cli_args.get("client_pem"),
            }
        )
    if targets:
        config["targets"] = targets

    if cli_args.get("hide_progress_bars"):
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


def wrap_evaluate(
    queue_in, queue_out, progress_console: Console = None, config: dict = None
) -> None:
    for target in iter(queue_in.get, None):
        log("[cyan]START[/cyan]", hostname=target.get('hostname'), port=target.get('port', 443), con=progress_console)
        try:
            state, evaluations = evaluate(
                console=progress_console,
                evaluations=config["evaluations"],
                **target,
                **config["defaults"],
            )
            if isinstance(state, TransportState):
                log(f"[cyan]DONE![/cyan] Negotiated {state.negotiated_protocol} {state.peer_address}", hostname=state.hostname, port=state.port, con=progress_console)
                data = state.to_dict()
                data["evaluations"] = evaluations
                queue_out.put(data)
        except Exception as ex:  # pylint: disable=broad-except
            logger.error(ex, exc_info=True)
            queue_out.put(
                {
                    "_metadata": {
                        "transport": {
                            "hostname": target.get("hostname"),
                            "port": target.get("port"),
                        }
                    },
                    "error": (type(ex).__name__, ex),
                }
            )


def cli():
    config, hide_progress_bars = configure()
    run_start = datetime.utcnow()
    queue_in = Queue()
    queue_out = Queue()
    queries = []
    num_targets = len(config.get("targets"))
    use_console = any(n.get("type") == "console" for n in config.get("outputs", []))
    if use_console:
        console.print(
            f"""[bold][aquamarine3] _        _       _       _
| |_ _ __(_)_   _(_) __ _| |___  ___ __ _ _ __
| __| '__| \\ \\ / / |/ _\\` | / __|/ __/ _\\` | '_\\
| |_| |  | |\\ V /| | (_| | \\__ \\ (_| (_| | | | |
 \\__|_|  |_| \\_/ |_|\\__,_|_|___/\\___\\__,_|_| |_|[/aquamarine3]
        [dark_sea_green2]SUCCESS[/dark_sea_green2] [khaki1]ISSUE[/khaki1] [light_coral]VULNERABLE[/light_coral][/bold]"""
        )
    log(f"[cyan]INFO![/cyan] Evaluating {num_targets} domain{'s' if num_targets >1 else ''}", aside="core", con=console if use_console else None)
    if hide_progress_bars:
        the_pool = Pool(
            cpu_count(),
            wrap_evaluate,
            (queue_in, queue_out, console if use_console else None, config),
        )
        for target in config.get("targets"):
            queue_in.put(target)
        for _ in range(num_targets):
            result = queue_out.get()
            queries.append(result)

    else:
        with Progress(
            TextColumn("{task.description}", table_column=Column(ratio=2)),
            MofNCompleteColumn(table_column=Column(ratio=1)),
            SpinnerColumn(table_column=Column(ratio=2)),
            transient=True,
        ) as progress:
            the_pool = Pool(
                cpu_count(),
                wrap_evaluate,
                (
                    queue_in,
                    queue_out,
                    progress.console if use_console else None,
                    config,
                ),
            )
            task_id = progress.add_task("Evaluating domains", total=num_targets)
            for target in config.get("targets"):
                queue_in.put(target)
            for _ in range(num_targets):
                result = queue_out.get()
                queries.append(result)
                progress.advance(task_id)
            progress.stop()

    queue_in.close()
    queue_in.join_thread()
    the_pool.close()
    execution_duration_seconds = (datetime.utcnow() - run_start).total_seconds()
    json_file = "".join(
        n["path"] for n in config.get("outputs", []) if n.get("type") == "json"
    )
    if json_file:
        json_path = Path(json_file)
        if json_path.is_file():
            json_path.unlink()
        json_path.write_text(
            json.dumps(
                {
                    "generator": "trivialscan",
                    "targets": [
                        f"{target.get('hostname')}:{target.get('port')}"
                        for target in config.get("targets")
                    ],
                    "execution_duration_seconds": execution_duration_seconds,
                    "date": datetime.utcnow().replace(microsecond=0).isoformat(),
                    "queries": queries,
                },
                sort_keys=True,
                indent=4,
                default=str,
            ),
            encoding="utf8",
        )
        log(f"[cyan]SAVED[/cyan] {json_file}", aside='core', con=console if use_console else None)

    log("[cyan]TOTAL[/cyan] Execution duration %.1f seconds" % execution_duration_seconds, aside='core', con=console if use_console else None)
    for result in queries:
        if result.get("error"):
            err, msg = result["error"]
            log(f'[light_coral]ERROR[/light_coral] {msg}', aside=err, con=console if use_console else None)


if __name__ == "__main__":
    cli()
