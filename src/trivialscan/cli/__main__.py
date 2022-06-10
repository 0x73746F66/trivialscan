import sys
import logging
import argparse
import json
from multiprocessing import Pool, cpu_count, Queue
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import validators
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Column
from rich.progress import Progress, MofNCompleteColumn, TextColumn, SpinnerColumn
from art import text2art
from . import log
from .. import evaluate
from ..config import load_config, get_config

__module__ = "trivialscan.cli"
__version__ = "3.0.0-devel"
REMOTE_URL = "https://gitlab.com/trivialsec/trivialscan/-/tree/devel"
APP_BANNER = text2art("trivialscan", font="tarty4")

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
console = Console()
logger = logging.getLogger(__name__)


def configure() -> tuple[dict, tuple[bool, bool, bool]]:
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
    parser.add_argument("--hide-banner", dest="hide_banner", action="store_true")
    parser.add_argument(
        "--no-multiprocessing", dest="synchronous_only", action="store_true"
    )
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
    if sys.stdout.isatty():
        log_format = "%(message)s"
        handlers.append(RichHandler(rich_tracebacks=True))
    logging.basicConfig(format=log_format, level=log_level, handlers=handlers)
    config = _cli_config(vars(args), args.config_file)
    if config["defaults"].get("skip_evaluations"):
        del config["defaults"]["skip_evaluations"]
    if config["defaults"].get("skip_evaluation_groups"):
        del config["defaults"]["skip_evaluation_groups"]
    return config, (args.hide_progress_bars, args.synchronous_only, args.hide_banner)


def _cli_config(cli_args: dict, filename: str | None) -> dict:
    # only overwrite value in config file if OVERRIDE cli args were defined
    if filename:
        custom = load_config(filename)
    else:
        custom = load_config()
    config = get_config(custom_values=custom)
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
        }
        for _target in config["targets"]:
            if parsed.hostname == _target["hostname"]:
                target = {**_target, **target}
                break
        targets.append(target)
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
        log(
            "[cyan]START[/cyan] Enumerating TLS negotiations",
            hostname=target.get("hostname"),
            port=target.get("port", 443),
            con=progress_console,
        )
        try:
            transport, evaluations = evaluate(
                console=progress_console,
                evaluations=config["evaluations"],
                **target,
                **config["defaults"],
            )
            state = transport.get_state()
            log(
                f"[cyan]DONE![/cyan] Negotiated {state.negotiated_protocol} {state.peer_address}",
                hostname=state.hostname,
                port=state.port,
                con=progress_console,
            )
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


def run_seq(config: dict, show_progress: bool, use_console: bool = False) -> list:
    queries = []
    progress = Progress(
        TextColumn(
            "Evaluating [bold cyan]{task.description}[/bold cyan]",
            table_column=Column(ratio=2),
        ),
        MofNCompleteColumn(table_column=Column(ratio=1)),
        SpinnerColumn(table_column=Column(ratio=2)),
        transient=True,
        disable=not show_progress,
    )
    task_id = progress.add_task("domains", total=len(config.get("targets")))
    for target in config.get("targets"):
        data = {
            "_metadata": {
                "transport": {
                    "hostname": target.get("hostname"),
                    "port": target.get("port"),
                }
            }
        }
        log(
            "[cyan]START[/cyan] Enumerating TLS negotiations",
            hostname=target.get("hostname"),
            port=target.get("port", 443),
            con=console if use_console else None,
        )
        try:
            if show_progress:
                progress.update(
                    task_id,
                    refresh=True,
                    description=f'{target.get("hostname")}:{target.get("port")}',
                )
                progress.start()
                transport, evaluations = evaluate(
                    console=progress.console if use_console else None,
                    evaluations=config["evaluations"],
                    **target,
                    **config["defaults"],
                )
                progress.advance(task_id)
                state = transport.get_state()
                log(
                    f"[cyan]DONE![/cyan] {state.peer_address}",
                    hostname=state.hostname,
                    port=state.port,
                    con=progress.console if use_console else None,
                )
                data = state.to_dict()
                data["evaluations"] = evaluations
            else:
                transport, evaluations = evaluate(
                    console=console if use_console else None,
                    evaluations=config["evaluations"],
                    **target,
                    **config["defaults"],
                )
                log(
                    f"[cyan]DONE![/cyan] Negotiated {state.negotiated_protocol} {state.peer_address}",
                    hostname=state.hostname,
                    port=state.port,
                    con=console if use_console else None,
                )
                state = transport.get_state()
                data = state.to_dict()
                data["evaluations"] = evaluations
        except Exception as ex:  # pylint: disable=broad-except
            logger.error(ex, exc_info=True)
            data["error"] = (type(ex).__name__, ex)
        finally:
            progress.stop()
        queries.append(data)

    return queries


def run_parra(config: dict, show_progress: bool, use_console: bool = False) -> list:
    queries = []
    num_targets = len(config.get("targets"))
    queue_in = Queue()
    queue_out = Queue()
    if show_progress:
        with Progress(
            TextColumn(
                "Evaluating [bold cyan]{task.description}[/bold cyan]",
                table_column=Column(ratio=2),
            ),
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
            task_id = progress.add_task("domains", total=num_targets)
            for target in config.get("targets"):
                queue_in.put(target)
            for _ in range(num_targets):
                result = queue_out.get()
                queries.append(result)
                progress.advance(task_id)
            progress.stop()
    else:
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

    queue_in.close()
    queue_in.join_thread()
    the_pool.close()

    return queries


def cli():
    config, flags = configure()
    hide_progress_bars, synchronous_only, hide_banner = flags
    run_start = datetime.utcnow()
    queries = []
    num_targets = len(config.get("targets"))
    use_console = any(n.get("type") == "console" for n in config.get("outputs", []))
    if use_console:
        if not hide_banner:
            console.print(
                f"""[bold][aquamarine3]{APP_BANNER}[/aquamarine3]
        [dark_sea_green2]SUCCESS[/dark_sea_green2] [khaki1]ISSUE[/khaki1] [light_coral]VULNERABLE[/light_coral][/bold]"""
            )
    log(
        f"[cyan]INFO![/cyan] Evaluating {num_targets} domain{'s' if num_targets >1 else ''}",
        aside="core",
        con=console if use_console else None,
    )
    if synchronous_only or num_targets == 1:
        queries = run_seq(config, not hide_progress_bars, use_console)
    else:
        queries = run_parra(config, not hide_progress_bars, use_console)

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
        log(
            f"[cyan]SAVED[/cyan] {json_file}",
            aside="core",
            con=console if use_console else None,
        )

    log(
        "[cyan]TOTAL[/cyan] Execution duration %.1f seconds"
        % execution_duration_seconds,
        aside="core",
        con=console if use_console else None,
    )
    for result in queries:
        if result.get("error"):
            err, msg = result["error"]
            log(
                f"[light_coral]ERROR[/light_coral] {msg}",
                aside=err,
                con=console if use_console else None,
            )


if __name__ == "__main__":
    cli()
