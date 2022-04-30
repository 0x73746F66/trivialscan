import platform
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
from rich import inspect, print
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress
from trivialscan import __version__, analyse, validator, pci, nist, fips
from trivialscan.scores import Score
from trivialscan.cli import config, outputs

__module__ = "trivialscan.cli"

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"
DEBUG = False


def update_bar(progress, task):
    def progress_bar(completed: int = None):
        if isinstance(completed, int):
            progress.update(task, completed=completed)
        else:
            progress.update(task, advance=1)

    return progress_bar


def wrap_console(results: dict, summary_only: bool = False):
    console = Console()
    console.print("\n")
    for result in results["validations"]:
        console.print(result.get("output"))

    if summary_only:
        console.print(config.RATING_ASCII[results["rating"]], style=results["color"])
    else:
        console.print(results["score"])


def no_progressbar(data: list):
    yield from data


def wrap_analyse(params: dict) -> dict:
    err = None
    try:
        _, validations = analyse(**params)
    except Exception as ex:
        err = str(ex)
        validations = []
    target = f"{params['host']}:{params['port']}"
    results = {"json": outputs.prepare_json(validations, target), "validations": []}
    for result in validations:
        data = {"target": target}
        if DEBUG and hasattr(result, "transport"):
            inspect(result.transport)
        if DEBUG and hasattr(result, "metadata"):
            inspect(result.metadata)
        if isinstance(result, validator.RootCertValidator):
            data["output"] = outputs.root_outputs(result)
        if isinstance(result, validator.PeerCertValidator):
            data["output"] = outputs.peer_outputs(result)
        if isinstance(result, validator.LeafCertValidator):
            data["output"] = outputs.server_outputs(result)
        results["validations"].append(data)

    if not results["validations"]:
        results["json"] = [{"target": target, "error": err}]
        results["score"] = None
    else:
        score_card = Score(validations)
        if score_card.rating == "F":
            rating_color = config.CLI_COLOR_NOK
        elif score_card.rating.startswith("A"):
            rating_color = config.CLI_COLOR_OK
        else:
            rating_color = config.CLI_COLOR_ALERT
        results["color"] = rating_color
        results["rating"] = score_card.rating
        results["score"] = outputs.table_score(score_card, rating_color, target)

    return results


def cli():
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
        "--pci-dss",
        help="Include PCI DSS requirements assertions",
        dest="show_pci",
        action="store_true",
    )
    parser.add_argument(
        "--nist-strict-mode",
        help="Include NIST SP800-131A strict mode assertions",
        dest="show_nist",
        action="store_true",
    )
    parser.add_argument(
        "--fips-nist-transition-mode",
        help="Include FIPS 140-2 transition to NIST SP800-131A assertions",
        dest="show_fips",
        action="store_true",
    )
    parser.add_argument(
        "--disable-sni",
        help="Do not negotiate SNI using INDA encoded host",
        dest="disable_sni",
        action="store_true",
    )
    parser.add_argument(
        "--show-private-key",
        help="If the private key is exposed, show it in the results",
        dest="show_private_key",
        action="store_true",
    )
    parser.add_argument(
        "-s",
        "--summary-only",
        help="Do not include informational details, show only validation outcomes",
        dest="summary_only",
        action="store_true",
    )
    parser.add_argument(
        "--hide-validation-details",
        help="Do not include detailed validation messages in output",
        dest="hide_validation_details",
        action="store_true",
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
    DEBUG = log_level == logging.DEBUG  # noqa: F841

    def version():
        print(
            f"{__version__} Python {sys.version} {platform.platform()} {platform.uname().node} {platform.uname().release} {platform.version()}"
        )

    if args.show_version:
        version()
        sys.exit(0)

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

    if args.hide_validation_details:
        config.SERVER_SKIP.append("verification_details")
        config.PEER_SKIP.append("verification_details")
        config.ROOT_SKIP.append("verification_details")
    if args.show_private_key:
        config.SERVER_SKIP.remove("certificate_private_key_pem")
        config.PEER_SKIP.remove("certificate_private_key_pem")
        config.ROOT_SKIP.remove("certificate_private_key_pem")

    if not args.show_nist:
        nist_keys = [
            nist.VALIDATION_CA_TRUST,
            nist.VALIDATION_WEAK_KEY,
            nist.VALIDATION_WEAK_CIPHER,
            nist.VALIDATION_WEAK_PROTOCOL,
            nist.VALIDATION_MTLS,
        ]
        config.SERVER_SKIP.extend(nist_keys)
        config.PEER_SKIP.extend(nist_keys)
        config.ROOT_SKIP.extend(nist_keys)

    if not args.show_fips:
        fips_keys = [
            fips.VALIDATION_CA_TRUST,
            fips.VALIDATION_WEAK_KEY,
            fips.VALIDATION_WEAK_CIPHER,
            fips.VALIDATION_WEAK_PROTOCOL,
            fips.VALIDATION_MTLS,
        ]
        config.SERVER_SKIP.extend(fips_keys)
        config.PEER_SKIP.extend(fips_keys)
        config.ROOT_SKIP.extend(fips_keys)

    if not args.show_pci:
        pci_keys = [
            pci.VALIDATION_CA_TRUST,
            pci.VALIDATION_WEAK_KEY,
            pci.VALIDATION_WEAK_CIPHER,
            pci.VALIDATION_WEAK_PROTOCOL,
            pci.VALIDATION_DEPRECATED_ALGO,
            pci.VALIDATION_KNOWN_VULN_COMPRESSION,
            pci.VALIDATION_KNOWN_VULN_RENEGOTIATION,
            pci.VALIDATION_KNOWN_VULN_SESSION_RESUMPTION,
        ]
        config.SERVER_SKIP.extend(pci_keys)
        config.PEER_SKIP.extend(pci_keys)
        config.ROOT_SKIP.extend(pci_keys)

    if args.summary_only:
        config.SERVER_SKIP.extend(config.SUMMARY_SKIP)
        config.PEER_SKIP.extend(config.SUMMARY_SKIP)
        config.ROOT_SKIP.extend(config.SUMMARY_SKIP)

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
                        "generator": __version__,
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
                wrap_console(result, summary_only=args.summary_only)


if __name__ == "__main__":
    cli()
