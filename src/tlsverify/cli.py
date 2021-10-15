import sys
import logging
import argparse
from datetime import datetime
import validators
from OpenSSL.crypto import X509
from rich import inspect
from rich.console import Console
from rich.style import Style
from rich.logging import RichHandler
from rich.progress import Progress
from . import exceptions, verify
from .validator import CertValidator, PeerCertValidator, Validator
from .transport import Transport


__module__ = 'tlsverify.cli'

def main(host :str, port :int = 443, cafiles :list = None, use_sni :bool = True, client_pem :str = None, tmp_path_prefix :str = '/tmp', debug :bool = False) -> tuple[bool,list[Validator]]:
    if not isinstance(port, int):
        raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    if not isinstance(client_pem, str) and client_pem is not None:
        raise TypeError(f"provided an invalid type {type(client_pem)} for client_pem, expected list")
    if not isinstance(cafiles, list) and cafiles is not None:
        raise TypeError(f"provided an invalid type {type(cafiles)} for cafiles, expected list")
    if not isinstance(use_sni, bool):
        raise TypeError(f"provided an invalid type {type(use_sni)} for tlsext, expected list")
    if not isinstance(tmp_path_prefix, str):
        raise TypeError(f"provided an invalid type {type(tmp_path_prefix)} for tmp_path_prefix, expected str")

    evaluation_start = datetime.utcnow()
    results = []
    with Progress() as progress:
        prog_client_auth = progress.add_task("[cyan]Client Authentication...", total=5)
        prog_tls_nego = progress.add_task("[cyan]Negotiating TLS...", total=7)
        prog_server_val = progress.add_task("[cyan]TLS Validation...", total=5)

        while not progress.finished:
            progress.update(prog_client_auth, advance=1)
            progress.update(prog_tls_nego, advance=1)
            validator = CertValidator()
            transport = Transport(host, port)
            if client_pem is None:
                progress.update(prog_client_auth, visible=False)
            else:
                transport.pre_client_authentication_check(client_pem_path=client_pem, updater=(progress, prog_client_auth))
            if not transport.connect_least_secure(cafiles=cafiles, use_sni=use_sni, updater=(progress, prog_tls_nego)) or not isinstance(transport.server_certificate, X509):
                raise exceptions.ValidationError(exceptions.VALIDATION_ERROR_TLS_FAILED)
            progress.update(prog_client_auth, completed=5)
            progress.update(prog_tls_nego, completed=7)
            if isinstance(tmp_path_prefix, str):
                validator.tmp_path_prefix = tmp_path_prefix
            validator.mount(transport)
            progress.update(prog_server_val, advance=1)
            validator.verify(updater=(progress, prog_tls_nego))
            progress.update(prog_server_val, advance=1)
            prog_chain_val = progress.add_task("[cyan]Certificate Chain Validation...", total=len(validator._pem_certificate_chain))
            validator.verify_chain(updater=(progress, prog_tls_nego))
            results = validator.peer_validations
            progress.update(prog_server_val, completed=5)
            progress.update(prog_chain_val, completed=len(validator._pem_certificate_chain))
            results.append(validator)

    console = Console()
    valid = all([v.certificate_valid for v in results])
    for result in results:
        if debug:
            inspect(result.transport, title=result.transport.negotiated_protocol)
        console.print(result.to_rich())
        print('\n\n')
    result_style = Style(color='green' if valid else 'bright_red')
    console.print('\nValid ✓✓✓' if valid else '\nNot Valid. There where validation errors', style=result_style)
    console.print(f'Evaluation duration seconds {(datetime.utcnow() - evaluation_start).total_seconds()}')

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="*")
    parser.add_argument('-H', '--host', help='host to check', dest='host', required=True)
    parser.add_argument('-p', '--port', help='TLS port of host', dest='port', default=443)
    parser.add_argument('-c', '--cafiles', help='path to PEM encoded CA bundle file, url or file path accepted', dest='cafiles', default=None)
    parser.add_argument('-C', '--client-pem', help='path to PEM encoded client certificate, url or file path accepted', dest='client_pem', default=None)
    parser.add_argument('-t', '--tmp-path-prefix', help='local file path to use as a prefix when saving temporary files such as those being fetched for client authorization', dest='tmp_path_prefix', default='/tmp')
    parser.add_argument('--disable-sni', help='Do not negotiate SNI using INDA encoded host', dest='disable_sni', action="store_true")
    parser.add_argument('-b', '--progress-bars', help='Show task progress bars', dest='show_progress', action="store_true")
    parser.add_argument('-v', '--errors-only', help='set logging level to ERROR (default CRITICAL)', dest='log_level_error', action="store_true")
    parser.add_argument('-vv', '--warning', help='set logging level to WARNING (default CRITICAL)', dest='log_level_warning', action="store_true")
    parser.add_argument('-vvv', '--info', help='set logging level to INFO (default CRITICAL)', dest='log_level_info', action="store_true")
    parser.add_argument('-vvvv', '--debug', help='set logging level to DEBUG (default CRITICAL)', dest='log_level_debug', action="store_true")
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
    log_format = '%(asctime)s - %(name)s - [%(levelname)s] %(message)s'
    if sys.stdout.isatty():
        log_format = '%(message)s'
        handlers.append(RichHandler(rich_tracebacks=True))
    logging.basicConfig(
        format=log_format,
        level=log_level,
        handlers=handlers
    )
    debug = log_level==logging.DEBUG
    if args.show_progress:
        main(
            args.host,
            int(args.port),
            cafiles=args.cafiles,
            use_sni=not args.disable_sni,
            client_pem=args.client_pem,
            tmp_path_prefix=args.tmp_path_prefix,
            debug=debug
        )
    else:
        evaluation_start = datetime.utcnow()
        valid, results = verify(
            args.host,
            int(args.port),
            cafiles=args.cafiles,
            use_sni=not args.disable_sni,
            client_pem=args.client_pem,
            tmp_path_prefix=args.tmp_path_prefix,
        )
        console = Console()
        for result in results:
            if debug:
                inspect(result.transport, title=result.transport.negotiated_protocol)
                inspect(result.metadata, title=result.metadata.certificate_subject)
            console.print(result.to_rich())
            print('\n\n')
        result_style = Style(color='green' if valid else 'bright_red')
        console.print('\nValid ✓✓✓' if valid else '\nNot Valid. There where validation errors', style=result_style)
        console.print(f'Evaluation duration seconds {(datetime.utcnow() - evaluation_start).total_seconds()}')
