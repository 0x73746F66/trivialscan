import sys
import logging
from multiprocessing import Pool, cpu_count, Queue
from datetime import datetime
from rich.console import Console
from rich.table import Column
from rich.progress import Progress, MofNCompleteColumn, TextColumn, SpinnerColumn
from art import text2art
from . import log
from .. import trivialscan
from ..outputs.json import save_to


__module__ = "trivialscan.cli.scan"
APP_BANNER = text2art("trivialscan", font="tarty4")

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
console = Console()
logger = logging.getLogger(__name__)


def wrap_trivialscan(
    queue_in, queue_out, progress_console: Console = None, config: dict = None
) -> None:
    for target in iter(queue_in.get, None):
        log(
            "[cyan]START[/cyan] Probing TLS",
            hostname=target.get("hostname"),
            port=target.get("port", 443),
            con=progress_console,
        )
        try:
            transport = trivialscan(
                console=progress_console,
                config=config,
                **target,
            )
            log(
                f"[cyan]DONE![/cyan] Negotiated {transport.store.tls_state.negotiated_protocol} {transport.store.tls_state.peer_address}",
                hostname=transport.store.tls_state.hostname,
                port=transport.store.tls_state.port,
                con=progress_console,
            )
            data = transport.store.to_dict()
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
            "[cyan]START[/cyan] Probing TLS",
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
                transport = trivialscan(
                    console=progress.console if use_console else None,
                    config=config,
                    **target,
                )
                progress.advance(task_id)
                log(
                    f"[cyan]DONE![/cyan] {transport.store.tls_state.peer_address}",
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    con=progress.console if use_console else None,
                )
                data = transport.store.to_dict()

            else:
                transport = trivialscan(
                    console=console if use_console else None,
                    config=config,
                    **target,
                )
                log(
                    f"[cyan]DONE![/cyan] Negotiated {transport.store.tls_state.negotiated_protocol} {transport.store.tls_state.peer_address}",
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    con=console if use_console else None,
                )
                data = transport.store.to_dict()

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
                "[bold cyan]{task.description}[/bold cyan]"
                + f" ({cpu_count()} threads)",
                table_column=Column(ratio=2),
            ),
            MofNCompleteColumn(table_column=Column(ratio=1)),
            SpinnerColumn(table_column=Column(ratio=2)),
            transient=True,
        ) as progress:
            the_pool = Pool(
                cpu_count(),
                wrap_trivialscan,
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
    else:
        the_pool = Pool(
            cpu_count(),
            wrap_trivialscan,
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


def scan(config: dict, **flags):
    no_stdout = flags.get("quiet", False)
    hide_progress_bars = True if no_stdout else flags.get("hide_progress_bars", False)
    hide_banner = True if no_stdout else flags.get("hide_banner", False)
    synchronous_only = flags.get("synchronous_only", False)
    log_level = flags.get("log_level", logging.ERROR)
    run_start = datetime.utcnow()
    queries = []
    num_targets = len(config.get("targets"))
    use_console = (
        any(n.get("type") == "console" for n in config.get("outputs", []))
        and not no_stdout
    )
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
    json_output = [
        n["path"] for n in config.get("outputs", []) if n.get("type") == "json"
    ]
    if json_output:
        for json_file in json_output:
            json_path = save_to(
                template_filename=json_file,
                data={
                    "generator": "trivialscan",
                    "targets": [
                        f"{target.get('hostname')}:{target.get('port')}"
                        for target in config.get("targets")
                    ],
                    "execution_duration_seconds": execution_duration_seconds,
                    "date": datetime.utcnow().replace(microsecond=0).isoformat(),
                    "queries": queries,
                },
                track_changes=flags.get("track_changes", False),
                tracking_template_filename=flags.get("previous_report"),
            )
            log(
                f"[cyan]SAVED[/cyan] {json_path}",
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
            if not use_console and log_level >= logging.ERROR:
                print(err)
