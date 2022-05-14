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
from .. import query_hostname
from ..config import get_config


__module__ = "trivialscan.cli"

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
console = Console()


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

    cli_args = {"defaults": vars(args)}
    base_config = get_config(args.config_file)
    return {**base_config, **cli_args}


def wrap_analyse(
    queue_in, queue_out, progress_console: Console = None, config: dict = None
) -> None:
    use_console = isinstance(progress_console, Console)
    logger = logging.getLogger(__name__)
    for hostname, port in iter(queue_in.get, None):
        if use_console:
            progress_console.print(
                f"{hostname}:{port} [cyan]START[/cyan]", highlight=False
            )
        try:
            state, evaluations = query_hostname(
                hostname, int(port), progress_console, config
            )
            if isinstance(state, TransportState):
                if use_console:
                    progress_console.print(
                        f"{state.hostname}:{state.port} [blue]INFO![/blue] negotiated {state.negotiated_protocol}",
                        highlight=False,
                    )
                data = state.to_dict()
                data["evaluations"] = evaluations
                queue_out.put(data)
        except Exception as ex:  # pylint: disable=broad-except
            logger.exception(ex)
            queue_out.put(
                {
                    "_metadata": {"transport": {"hostname": hostname, "port": port}},
                    "error": str(ex),
                }
            )


def cli():
    config = configure()
    targets = []
    for target in config["defaults"].get("targets", []):
        if not target.startswith("http"):
            target = f"https://{target}"
        parsed = urlparse(target)
        if validators.domain(parsed.hostname) is not True:
            raise AttributeError(f"URL {target} hostname {parsed.hostname} is invalid")
        targets.append((parsed.hostname, 443 if not parsed.port else parsed.port))

    run_start = datetime.utcnow()
    queue_in = Queue()
    queue_out = Queue()
    queries = []
    num_targets = len(targets)
    use_console = any(
        True for n in config.get("outputs", []) if n.get("type") == "console"
    )

    with Progress(
        TextColumn("{task.description}", table_column=Column(ratio=2)),
        MofNCompleteColumn(table_column=Column(ratio=1)),
        SpinnerColumn(table_column=Column(ratio=2)),
        expand=False,
    ) as progress:
        the_pool = Pool(
            cpu_count(),
            wrap_analyse,
            (queue_in, queue_out, progress.console if use_console else None, config),
        )
        task_id = progress.add_task("Evaluating domains", total=num_targets)
        for target in targets:
            queue_in.put(target)
        for _ in range(num_targets):
            result = queue_out.get()
            if use_console:
                progress.console.print(
                    f'{result["_metadata"]["transport"]["hostname"]}:{result["_metadata"]["transport"]["port"]} [green]DONE![/green]',
                    highlight=False,
                )
            queries.append(result)
            progress.advance(task_id)
        progress.update(task_id, completed=num_targets)
        progress.stop_task(task_id)

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
                    "targets": [f"{hostname}:{port}" for hostname, port in targets],
                    "execution_duration_seconds": execution_duration_seconds,
                    "date": datetime.utcnow().replace(microsecond=0).isoformat(),
                    "queries": queries,
                },
                sort_keys=True,
                default=str,
            ),
            encoding="utf8",
        )
    if use_console:
        for result in queries:
            if result.get("error"):
                console.print(result["error"])


if __name__ == "__main__":
    cli()
