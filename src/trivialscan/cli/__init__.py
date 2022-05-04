import json
import sys
import logging
import argparse
import threading
from multiprocessing import Pool, cpu_count
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import validators
import progressbar
from rich import print  # pylint: disable=redefined-builtin
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress

__module__ = "trivialscan.cli"

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"


def update_bar(progress, task):
    def progress_bar(completed: int = None):
        if isinstance(completed, int):
            progress.update(task, completed=completed)
        else:
            progress.update(task, advance=1)

    return progress_bar


def wrap_console(results: dict):
    console = Console()
    console.print("\n")
    for result in results["validations"]:
        console.print(result.get("output"))
    console.print(results["score"])


def no_progressbar(data: list):
    yield from data


def wrap_analyse(params: dict) -> dict:
    err = None
    target = f"{params['host']}:{params['port']}"
    results = {"json": {}, "validations": []}
    results["json"] = [{"target": target, "error": err}]
    results["score"] = None

    return results


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "targets",
        nargs="*",
        help="All unnamed arguments are hosts (and ports) targets to test. ~$ trivialscan google.com:443 github.io owasp.org:80",
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

    domains = []
    for target in args.targets:
        if not target.startswith("http"):
            target = f"https://{target}"
        parsed = urlparse(target)
        if validators.domain(parsed.hostname) is not True:
            raise AttributeError(f"URL {target} hostname {parsed.hostname} is invalid")
        port = 443 if not parsed.port else parsed.port
        domains.append(
            {
                "host": parsed.hostname,
                "port": port,
                "cafiles": args.cafiles,
                "use_sni": not args.disable_sni,
                "client_pem": args.client_pem,
                "tmp_path_prefix": args.tmp_path_prefix,
            }
        )

    run_start = datetime.utcnow()
    with Progress() as progress:
        if args.hide_progress_bars:
            progressbar.progressbar = no_progressbar
        else:
            task = progress.add_task("Scanning hosts", total=len(domains))

        results = []
        thread = threading.Thread(target=lambda: None)
        thread.start()
        with Pool(processes=min(cpu_count(), len(domains))) as pool:
            for result in pool.imap_unordered(wrap_analyse, domains):
                results.append(result)
                if not args.hide_progress_bars:
                    progress.advance(task)

        if not args.hide_progress_bars:
            progress.remove_task(task)

        execution_duration_seconds = (datetime.utcnow() - run_start).total_seconds()
        if args.json_file:
            json_path = Path(args.json_file)
            if json_path.is_file():
                json_path.unlink()
            json_path.write_text(
                json.dumps(
                    {
                        "generator": "trivialscan",
                        "targets": [f"{d['host']}:{d['port']}" for d in domains],
                        "execution_duration_seconds": execution_duration_seconds,
                        "date": datetime.utcnow().replace(microsecond=0).isoformat(),
                        "evaluations": [val for val in [v["json"] for v in results]],
                    },
                    sort_keys=True,
                    default=str,
                ),
                encoding="utf8",
            )
        else:
            for result in results:
                if not result["validations"]:
                    print(result["json"][0]["error"])
                    continue
                wrap_console(result)


if __name__ == "__main__":
    cli()
