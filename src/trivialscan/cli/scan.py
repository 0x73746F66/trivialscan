import signal
import sys
import logging
from multiprocessing import Pool, cpu_count, Queue
from datetime import datetime

from rich.console import Console
from rich.table import Column
from rich.progress import (
    Progress,
    MofNCompleteColumn,
    TextColumn,
    SpinnerColumn,
)
from art import text2art

from .. import cli, constants, trivialscan
from ..util import camel_to_snake, update_cloud, make_data
from ..outputs.json import save_to, save_partial

__module__ = "trivialscan.cli.scan"
APP_BANNER = text2art("trivialscan", font="tarty4")

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"
console = Console()
logger = logging.getLogger(__name__)


def wrap_trivialscan(
    queue_in, queue_out, progress_console: Console = None, config: dict = None
) -> None:
    handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGINT, handler)
    use_icons = any(
        n.get("type") == "console" and n.get("use_icons")
        for n in config.get("outputs", [])
    )
    try:
        for target in iter(queue_in.get, None):
            try:
                transport = trivialscan(
                    console=progress_console,
                    config=config,
                    **target,
                )
                cli.outputln(
                    f"Negotiated {transport.store.tls_state.negotiated_protocol} {transport.store.tls_state.peer_address}",
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    result_text="DONE!",
                    con=progress_console,
                    use_icons=use_icons,
                )
                data = transport.store.to_dict()
                log_files = save_partial(
                    config=config,
                    when="per_host",
                    data_type=f"{transport.store.tls_state.hostname}:{transport.store.tls_state.port}",
                    data=data,
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    peer_address=transport.store.tls_state.peer_address,
                    negotiated_protocol=transport.store.tls_state.negotiated_protocol,
                    negotiated_cipher=transport.store.tls_state.negotiated_cipher,
                    account_name=config.get("account_name"),
                    client_name=config.get("client_name"),
                    project_name=config.get("project_name"),
                )
                for log_file in log_files:
                    cli.outputln(
                        log_file,
                        aside="core",
                        result_text="SAVED",
                        result_icon=":floppy_disk:",
                        con=progress_console,
                        use_icons=use_icons,
                    )
                for cert in transport.store.tls_state.certificates:
                    log_files = save_partial(
                        config=config,
                        when="per_certificate",
                        data_type=cert.subject,
                        data={
                            **cert.to_dict(),
                            **{
                                "evaluations": [
                                    e
                                    for e in transport.store.evaluations
                                    if e.group == "certificate"
                                    and e.metadata.get("sha1_fingerprint")
                                    == cert.sha1_fingerprint
                                ]
                            },
                        },
                        hostname=transport.store.tls_state.hostname,
                        port=transport.store.tls_state.port,
                        certificate_type=camel_to_snake(type(cert).__name__),
                        sha1_fingerprint=cert.sha1_fingerprint,
                        md5_fingerprint=cert.md5_fingerprint,
                        sha256_fingerprint=cert.sha256_fingerprint,
                        serial_number_hex=cert.serial_number_hex,
                        public_key_type=cert.public_key_type,
                        public_key_size=cert.public_key_size,
                        subject_key_identifier=cert.subject_key_identifier,
                        spki_fingerprint=cert.spki_fingerprint,
                        version=cert.version,
                        validation_level=cert.validation_level,
                        not_before=cert.not_before,
                        not_after=cert.not_after,
                        account_name=config.get("account_name"),
                        client_name=config.get("client_name"),
                        project_name=config.get("project_name"),
                    )
                    for log_file in log_files:
                        cli.outputln(
                            log_file,
                            aside="core",
                            result_text="SAVED",
                            result_icon=":floppy_disk:",
                            con=progress_console,
                            use_icons=use_icons,
                        )
                queue_out.put(data)

            except Exception as ex:  # pylint: disable=broad-except
                logger.error(ex, exc_info=True)
                queue_out.put(
                    {
                        "transport": {
                            "hostname": target.get("hostname"),
                            "port": target.get("port"),
                        },
                        "error": (type(ex).__name__, ex),
                    }
                )
    except KeyboardInterrupt:
        queue_out.put(
            {
                "transport": {
                    "hostname": target.get("hostname"),
                    "port": target.get("port"),
                },
                "error": ("KeyboardInterrupt", "Operation cancelled (Ctrl+C)"),
            }
        )


def run_seq(config: dict, show_progress: bool, use_console: bool = False) -> list:
    use_icons = any(
        n.get("type") == "console" and n.get("use_icons")
        for n in config.get("outputs", [])
    )
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
            "transport": {
                "hostname": target.get("hostname"),
                "port": target.get("port"),
            }
        }
        transport = None
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
                cli.outputln(
                    transport.store.tls_state.peer_address or "PROBE Protocol SSL/TLS",
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    result_text="DONE!",
                    con=progress.console if use_console else None,
                    use_icons=use_icons,
                )
                data = transport.store.to_dict()

            else:
                transport = trivialscan(
                    console=console if use_console else None,
                    config=config,
                    **target,
                )
                cli.outputln(
                    f"Negotiated {transport.store.tls_state.negotiated_protocol} {transport.store.tls_state.peer_address}",
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    con=console if use_console else None,
                    use_icons=use_icons,
                )
                data = transport.store.to_dict()

            queries.append(data)
            log_files = save_partial(
                config=config,
                when="per_host",
                data_type=f"{transport.store.tls_state.hostname}:{transport.store.tls_state.port}",
                data=data,
                hostname=transport.store.tls_state.hostname,
                port=transport.store.tls_state.port,
                peer_address=transport.store.tls_state.peer_address,
                negotiated_protocol=transport.store.tls_state.negotiated_protocol,
                negotiated_cipher=transport.store.tls_state.negotiated_cipher,
                account_name=config.get("account_name"),
                client_name=config.get("client_name"),
                project_name=config.get("project_name"),
            )
            for log_file in log_files:
                cli.outputln(
                    log_file,
                    aside="core",
                    result_text="SAVED",
                    result_icon=":floppy_disk:",
                    con=console if use_console else None,
                    use_icons=use_icons,
                )
            for cert in transport.store.tls_state.certificates:
                log_files = save_partial(
                    config=config,
                    when="per_certificate",
                    data_type=cert.subject,
                    data={
                        **cert.to_dict(),
                        **{
                            "evaluations": [
                                e
                                for e in transport.store.evaluations
                                if e.group == "certificate"
                                and e.metadata.get("sha1_fingerprint")
                                == cert.sha1_fingerprint
                            ]
                        },
                    },
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    certificate_type=camel_to_snake(type(cert).__name__),
                    sha1_fingerprint=cert.sha1_fingerprint,
                    md5_fingerprint=cert.md5_fingerprint,
                    sha256_fingerprint=cert.sha256_fingerprint,
                    serial_number_hex=cert.serial_number_hex,
                    public_key_type=cert.public_key_type,
                    public_key_size=cert.public_key_size,
                    subject_key_identifier=cert.subject_key_identifier,
                    spki_fingerprint=cert.spki_fingerprint,
                    version=cert.version,
                    validation_level=cert.validation_level,
                    not_before=cert.not_before,
                    not_after=cert.not_after,
                    account_name=config.get("account_name"),
                    client_name=config.get("client_name"),
                    project_name=config.get("project_name"),
                )
                for log_file in log_files:
                    cli.outputln(
                        log_file,
                        aside="core",
                        result_text="SAVED",
                        result_icon=":floppy_disk:",
                        con=console if use_console else None,
                        use_icons=use_icons,
                    )

        except KeyboardInterrupt:
            if use_console:
                progress.console.print(
                    "[cyan]Operation cancelled ([bold]Ctrl+C[/bold])[/cyan]"
                )
        except Exception as ex:  # pylint: disable=broad-except
            logger.error(ex, exc_info=True)
        finally:
            progress.stop()

    return queries


def run_parra(config: dict, show_progress: bool, use_console: bool = False) -> list:
    queries = []
    num_targets = len(config.get("targets"))
    queue_in = Queue()
    queue_out = Queue()
    progress = None
    try:
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
                progress.stop_task(task_id)
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
    except KeyboardInterrupt:
        if use_console:
            console.print(
                "[cyan]Operation cancelled ([bold]Ctrl+C[/bold]), terminating workers[/cyan]"
            )
    finally:
        the_pool.terminate()
        if isinstance(progress, Progress):
            progress.stop()

    return queries


def scan(config: dict, **flags):
    no_stdout = flags.get("quiet", False)
    hide_progress_bars = True if no_stdout else flags.get("hide_progress_bars", False)
    synchronous_only = flags.get("synchronous_only", False)
    run_start = datetime.utcnow()
    queries = []
    num_targets = len(config.get("targets"))
    use_console = (
        any(n.get("type") == "console" for n in config.get("outputs", []))
        and not no_stdout
    )
    use_icons = any(
        n.get("type") == "console" and n.get("use_icons")
        for n in config.get("outputs", [])
    )
    cli.outputln(
        f"Evaluating {num_targets} domain{'s' if num_targets >1 else ''}",
        aside="core",
        con=console if use_console else None,
        use_icons=use_icons,
    )
    if synchronous_only or num_targets == 1:
        queries = run_seq(config, not hide_progress_bars, use_console)
    else:
        queries = run_parra(config, not hide_progress_bars, use_console)

    execution_duration_seconds = (datetime.utcnow() - run_start).total_seconds()
    save_final(config, flags, queries, execution_duration_seconds, use_console)
    if config.get("account_name") and config.get("client_name") and config.get("token"):
        cli.outputln(
            "Storing results to the cloud",
            aside="core",
            con=console if use_console else None,
            use_icons=use_icons,
        )
        results_urls = update_cloud(queries, config, flags, execution_duration_seconds)
        from .__main__ import DASHBOARD_URL  # pylint: disable=import-outside-toplevel

        cli.outputln(
            f"View results online: {DASHBOARD_URL}/reports"
            if results_urls
            else "Unable to reach the Trivial Security servers",
            aside="core",
            result_level=constants.RESULT_LEVEL_INFO
            if results_urls
            else constants.RESULT_LEVEL_WARN,
            result_text="SAVED"
            if results_urls
            else constants.RESULT_LEVEL_WARN_DEFAULT,
            result_icon=":floppy_disk:"
            if results_urls
            else constants.CLI_ICON_MAP.get(constants.RESULT_LEVEL_WARN),
            con=console if use_console else None,
            use_icons=use_icons,
        )
    else:
        cli.outputln(
            "Not configured to save reports to the Cloud Dashboard",
            aside="core",
            con=console if use_console else None,
            use_icons=use_icons,
        )

    cli.outputln(
        "Execution duration %.1f seconds" % execution_duration_seconds,
        aside="core",
        result_text="TOTAL",
        con=console if use_console else None,
        use_icons=use_icons,
    )


def save_final(
    config: dict,
    flags: dict,
    queries: list[dict],
    execution_duration_seconds: int,
    use_console: bool,
) -> dict:
    data = make_data(config, queries)
    data["execution_duration_seconds"] = execution_duration_seconds
    json_output = [
        n["path"]
        for n in config.get("outputs", [])
        if n.get("type") == "json" and n.get("when", "final") == "final"
    ]
    use_icons = any(
        n.get("type") == "console" and n.get("use_icons")
        for n in config.get("outputs", [])
    )
    if json_output:
        for json_file in json_output:
            json_path = save_to(
                template_filename=json_file,
                data=data,
                track_changes=flags.get("track_changes", False),
                tracking_template_filename=flags.get("previous_report"),
                account_name=config.get("account_name"),
                client_name=config.get("client_name"),
                project_name=config.get("project_name"),
            )
            cli.outputln(
                json_path,
                aside="core",
                result_text="SAVED",
                result_icon=":floppy_disk:",
                con=console if use_console else None,
                use_icons=use_icons,
            )
    return data
