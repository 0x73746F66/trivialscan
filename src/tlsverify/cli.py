import argparse
import tlsverify

__module__ = 'tlsverify.cli'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', help='host to check', dest='host', required=True)
    parser.add_argument('-p', '--port', help='TLS port of host', dest='port', default=443)
    parser.add_argument('-c', '--cafiles', help='path to PEM encoded CA bundle file', dest='cafiles', default=None)
    parser.add_argument('--sni', help='Negotiate SNI via PyOpenSSL Connection set_tlsext_host_name and INDA encoded host', dest='tlsext', action="store_true")

    args = parser.parse_args()
    valid, validators = tlsverify.verify(args.host, args.port, cafiles=args.cafiles, tlsext=args.tlsext)
    for validator in validators:
        print(validator.tabulate())
        print('\n\n')
    print('\nValid ✓✓✓' if valid else '\nNot Valid. There where validation errors')

if __name__ == "__main__":
    main()
