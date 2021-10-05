import logging
import argparse
from datetime import datetime
from . import verify

__module__ = 'tlsverify.cli'

def cli():
    evaluation_start = datetime.utcnow()
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', help='host to check', dest='host', required=True)
    parser.add_argument('-p', '--port', help='TLS port of host', dest='port', default=443)
    parser.add_argument('-c', '--cafiles', help='path to PEM encoded CA bundle file, url or file path accepted', dest='cafiles', default=None)
    parser.add_argument('-C', '--client-pem', help='path to PEM encoded client certificate, url or file path accepted', dest='client_pem', default=None)
    parser.add_argument('-T', '--client-ca-pem', help='path to PEM encoded client CA certificate, url or file path accepted', dest='client_ca', default=None)
    parser.add_argument('--sni', help='Negotiate SNI via PyOpenSSL Connection set_tlsext_host_name and INDA encoded host', dest='tlsext', action="store_true")
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
    logging.basicConfig(
        format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s',
        level=log_level
    )
    valid, results = verify(args.host, int(args.port), cafiles=args.cafiles, tlsext=args.tlsext, client_pem=args.client_pem, client_ca=args.client_ca)
    for validator in results:
        print(validator.tabulate())
        print('\n\n')
    print('\nValid ✓✓✓' if valid else '\nNot Valid. There where validation errors')
    print(f'evaluation duration seconds {(datetime.utcnow() - evaluation_start).total_seconds()}')
