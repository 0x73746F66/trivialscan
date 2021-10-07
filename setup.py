from setuptools import setup, find_packages

setup(
    name="tls-verify",
    version="0.2.3",
    author='Christopher Langton',
    author_email='chris@langton.cloud',
    description="Validate the security of your TLS connections so that they deserve your trust.",
    long_description="""
# tls-verify

Validate the security of your TLS connections so that they deserve your trust.

## [Documentation](https://gitlab.com/chrislangton/py-tls-veryify/-/blob/main/docs/0.index.md)

## Basic Usage

`python3 -m pip install -U tls-verify`

```py
import tlsverify

host = 'google.com'
is_valid, results = tlsverify.verify(host)
print('\nValid ✓✓✓' if is_valid else '\nNot Valid. There where validation errors')
```

`python3 -m pip install pipx && pipx install tls-verify`

On the command-line:

```sh
tlsverify --help
```

produces:

```
usage: command-line.py [-h] -H HOST [-p PORT] [-c CAFILES] [-C CLIENT_PEM] [-T CLIENT_CA] [-t TMP_PATH_PREFIX]
                       [--sni] [-v] [-vv] [-vvv] [-vvvv]

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  host to check
  -p PORT, --port PORT  TLS port of host
  -c CAFILES, --cafiles CAFILES
                        path to PEM encoded CA bundle file, url or file path accepted
  -C CLIENT_PEM, --client-pem CLIENT_PEM
                        path to PEM encoded client certificate, url or file path accepted
  -T CLIENT_CA, --client-ca-pem CLIENT_CA
                        path to PEM encoded client CA certificate, url or file path accepted
  -t TMP_PATH_PREFIX, --tmp-path-prefix TMP_PATH_PREFIX
                        local file path to use as a prefix when saving temporary files such as those being fetched
                        for client authorization
  --sni                 Negotiate SNI via PyOpenSSL Connection set_tlsext_host_name and INDA encoded host
  -v, --errors-only     set logging level to ERROR (default CRITICAL)
  -vv, --warning        set logging level to WARNING (default CRITICAL)
  -vvv, --info          set logging level to INFO (default CRITICAL)
  -vvvv, --debug        set logging level to DEBUG (default CRITICAL)
```

## Features

- Certificate Formats
  - ✓ plaintext
  - ✓ PEM
  - ✓ ASN1/DER
  - ✓ pyOpenSSL object
  - ✓ python `cryptography` object
- TLS Information
  - ✓ negotiated_protocol
  - ✓ negotiated_cipher
  - ✓ RSA private key
  - ✓ DSA private key
- X.509 Information
  - ✓ certificate_subject
  - ✓ certificate_issuer
  - ✓ certificate_issuer_country
  - ✓ certificate_signature_algorithm
  - ✓ SNI
- Signatures
  - ✓ certificate_md5_fingerprint
  - ✓ certificate_sha1_fingerprint
  - ✓ certificate_sha256_fingerprint
  - ✓ certificate_pin_sha256
  - ✓ certificate_serial_number
  - ✓ certificate_serial_number_decimal
  - ✓ certificate_serial_number_hex
  - ✓ certificate_public_key_type
  - ✓ certificate_key_size
- ✓ Expiry date is future dated
- Hostname match
  - ✓ common name
  - ✓ subjectAltName
  - ✓ properly handle wildcard names
- ✓ certificate_is_self_signed
- Enumerate the TLS extensions to ensure all validations are performed (excluding non-standard or any custom extensions that may exist)
  - ✓ subjectAltName
  - ✓ issuerAlternativeName
  - ✓ authorityKeyIdentifier matches issuer subjectKeyIdentifier
  - ✓ keyUsage
  - ✓ extendedKeyUsage
  - ✓ inhibitAnyPolicy
  - ✓ basicConstraints ca
  - ✓ basicConstraints path_length
  - ✓ validate clientAuth subjects
- Authentication
  - ✓ clientAuth
- revocation
  - ✓ OCSP
- ✓ Root Certificate is a CA and in a trust store
- Validate the complete chain (a requirement for zero-trust)
  - ✓ correctly build the chain
  - ✓ All certs in the chain are not revoked
  - ✓ Intermediate key usages are verified
  - ✓ optionally; allow the user to include additional cacert bundle
  - optionally; client condition; path length is exactly 3 (Root CA, signer/issuer, server cert) regardless of tls extension basicConstraints path_length
- Not using known weak "x"
  - ✓ protocol
  - ✓ keys
  - ✓ signature algorithm
- ✓ CLI output evaluation duration
- ✓ OpenSSL verify errors are actually evaluated and reported instead of either terminate connection or simply ignored (default approach most use VERIFY_NONE we actually let openssl do verification and keep the connection open anyway)

## [Change Log](https://gitlab.com/chrislangton/py-tls-veryify/-/blob/main/docs/z.change-log.md)
    """,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/chrislangton/py-tls-veryify",
    project_urls={
        "Source": "https://gitlab.com/chrislangton/py-tls-veryify",
        "Documentation": "https://gitlab.com/chrislangton/py-tls-veryify/-/blob/main/docs/0.index.md",
        "Tracker": "https://gitlab.com/chrislangton/py-tls-veryify/-/issues",
    },
    classifiers=[
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    include_package_data=True,
    install_requires=[
        'certifi==2021.5.30',
        'cryptography==35.0.0',
        'asn1crypto==1.4.0',
        'certvalidator==0.11.1',
        'oscrypto==1.2.1',
        'pyOpenSSL==21.0.0',
        'validators==0.18.2',
        'idna==3.2',
        'tabulate==0.8.9'
    ],
    entry_points = {
        'console_scripts': ['tlsverify=tlsverify.cli:cli'],
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    options={"bdist_wheel": {"universal": "1"}},
)
