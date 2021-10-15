import os
import argparse
from pathlib import Path
from OpenSSL.crypto import dump_certificate, load_certificate, FILETYPE_ASN1, FILETYPE_TEXT, FILETYPE_PEM

# python dump-cert.py charles-proxy.crt charles-proxy-legacy.crt burp-ca-1.crt burp-ca-2.crt preact-cli.crt
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("certs", nargs="*")
    args = parser.parse_args()
    for cert_file in args.certs:
        if not cert_file.startswith('/'):
            cert_file = f'{os.path.dirname(os.path.realpath(__file__))}/{cert_file}'
        chk_path = Path(cert_file)
        if not chk_path.is_file():
            print(f'not a file {cert_file}')
        file_type = FILETYPE_ASN1
        if cert_file.endswith('.crt') or cert_file.endswith('.pem'): file_type = FILETYPE_PEM
        cert = load_certificate(file_type, chk_path.read_bytes())
        print(
            dump_certificate(FILETYPE_TEXT, cert).decode()
        )
