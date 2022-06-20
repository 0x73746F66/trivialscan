from copy import deepcopy
import sys
import logging
import json
from multiprocessing import Pool, cpu_count, Queue
from pathlib import Path
from datetime import datetime
from deepdiff import DeepDiff
from rich.console import Console
from rich.table import Column
from rich.progress import Progress, MofNCompleteColumn, TextColumn, SpinnerColumn
from art import text2art
from . import log
from .. import evaluate
from ..config import merge_lists_by_value

__module__ = "trivialscan.cli.scan"
APP_BANNER = text2art("trivialscan", font="tarty4")

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
console = Console()
logger = logging.getLogger(__name__)


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
                state = transport.get_state()
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


def track_delta(last: list[dict], current: list[dict]) -> list[dict]:
    exclude_paths = [
        "root['http']['headers']['headers']['date']",
        "root['iterable_item_added']",
        "root['iterable_item_removed']",
        "root['dictionary_item_added']",
        "root['dictionary_item_removed']",
        "root['attribute_added']",
        "root['attribute_removed']",
        "root['type_changes']",
        "root['values_changed']",
        "root['repetition_change']",
    ]
    results = []
    for last_query in last:
        for current_query in current:
            if (
                last_query["_metadata"]["transport"]["hostname"]
                != current_query["_metadata"]["transport"]["hostname"]
            ):
                continue
            result = deepcopy(current_query)
            ddiff = DeepDiff(
                last_query.get("_metadata", {}),
                current_query.get("_metadata", {}),
                ignore_order=True,
                exclude_paths=exclude_paths,
            )
            metadata = json.loads(
                ddiff.to_json(default_mapping={datetime: str}).replace(
                    '"root[', '"metadata['
                )
            )
            result["_metadata"] = {**current_query.get("_metadata", {}), **metadata}
            result["evaluations"] = []
            for last_evaluation in last_query.get("evaluations", []):
                for current_evaluation in current_query.get("evaluations", []):
                    if last_evaluation.get("key") != current_evaluation.get("key"):
                        continue
                    ddiff = DeepDiff(
                        last_evaluation, current_evaluation, ignore_order=True
                    )
                    extra = json.loads(
                        ddiff.to_json(default_mapping={datetime: str}).replace(
                            '"root[', '"evaluation['
                        )
                    )
                    result["evaluations"].append({**current_evaluation, **extra})
            results.append(result)
    return merge_lists_by_value(current, results)


def scan(config: dict, **flags):
    no_stdout = flags.get("quiet", False)
    hide_progress_bars = True if no_stdout else flags.get("hide_progress_bars", False)
    hide_banner = True if no_stdout else flags.get("hide_banner", False)
    synchronous_only = flags.get("synchronous_only", False)
    track_changes = flags.get("track_changes", False)
    previous_report = flags.get("previous_report")
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
    json_file = "".join(
        n["path"] for n in config.get("outputs", []) if n.get("type") == "json"
    )
    if json_file:
        json_path = Path(json_file)
        tracking_last = None
        if previous_report:
            prev_path = Path(previous_report)
            if track_changes:
                if prev_path.is_file():
                    try:
                        tracking_last = json.loads(prev_path.read_text(encoding="utf8"))
                    except json.decoder.JSONDecodeError as ex:
                        logger.warning(ex, exc_info=True)
        if track_changes and json_file != previous_report and json_path.is_file():
            try:
                tracking_last = json.loads(json_path.read_text(encoding="utf8"))
            except json.decoder.JSONDecodeError as ex:
                logger.warning(ex, exc_info=True)
        if track_changes and tracking_last:
            queries = track_delta(tracking_last.get("queries", []), queries)

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
            if not use_console and log_level >= logging.ERROR:
                print(err)
