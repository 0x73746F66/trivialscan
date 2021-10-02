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
    args = parser.parse_args()
    verify = tlsverify.Validator(args.host)
    verify.verify()
    metadata = verify.get_metadata()
    certificate_san = metadata['certificate_san']
    del metadata['certificate_san']
    certificate_extensions = metadata['certificate_extensions']
    del metadata['certificate_extensions']
    kv = [
        ['certificate_valid', verify.certificate_valid],
        ['certificate_chain_valid', verify.certificate_chain_valid],
        ['certificate_chain_validation_result', verify.certificate_chain_validation_result]
    ]
    kv += [['Error', err] for err in verify.certificate_verify_messages]
    kv += [[key, verify.validation_checks[key]] for key in verify.validation_checks.keys()]
    kv += [[key, metadata[key]] for key in metadata.keys()]
    kv += [[v['name'], any_to_string(v, ' ') if v['name'] not in v else any_to_string(v[v['name']], ' ')] for v in certificate_extensions]
    print(tabulate(kv, tablefmt='tsv', disable_numparse=True, colalign=("right",)))
