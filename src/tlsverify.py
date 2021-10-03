import argparse
import tlsverify
from tabulate import tabulate

__module__ = 'tlsverify.cli'

def any_to_string(value, delimiter='\n') -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and isinstance(value[0], str):
        return delimiter.join(value)
    if isinstance(value, list) and not isinstance(value[0], str):
        n = []
        for d in value:
            n.append(any_to_string(d, delimiter))
        return any_to_string(n)
    if isinstance(value, dict):
        return delimiter.join([f'{key}={str(value[key])}' for key in value.keys()])
    return str(value)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', help='host to check', dest='host', required=True)
    parser.add_argument('-p', '--port', help='TLS port of host', dest='port', default=443)
    parser.add_argument('-c', '--cafiles', help='path to PEM encoded CA bundle file', dest='cafiles', default=None)
    parser.add_argument('--sni', help='Negotiate SNI via PyOpenSSL Connection set_tlsext_host_name and INDA encoded host', dest='tlsext', action="store_true")

    args = parser.parse_args()
    valid, validators = tlsverify.verify(args.host, args.port, cafiles=args.cafiles, tlsext=args.tlsext)
    for validator in validators:
        metadata = validator.get_metadata()
        certificate_san = metadata['certificate_san']
        del metadata['certificate_san']
        certificate_extensions = metadata['certificate_extensions']
        del metadata['certificate_extensions']
        kv = [
            ['certificate_valid', validator.certificate_valid],
            ['certificate_chain_valid', validator.certificate_chain_valid],
            ['certificate_chain_validation_result', validator.certificate_chain_validation_result]
        ]
        kv += [['Error', err] for err in validator.certificate_verify_messages]
        kv += [[f'Check {key}', validator.validation_checks[key]] for key in validator.validation_checks.keys()]
        kv += [[key, metadata[key]] for key in metadata.keys()]
        kv += [[v['name'], any_to_string(v, ' ') if v['name'] not in v else any_to_string(v[v['name']], ' ')] for v in certificate_extensions]
        print(tabulate(kv, tablefmt='tsv', disable_numparse=True, colalign=("right",)))
        print('\n\n')
    print('\nValid ✓✓✓' if valid else '\nNot Valid. There where validation errors')
