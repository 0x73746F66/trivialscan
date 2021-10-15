from setuptools import setup, find_packages

setup(
    name="tls-verify",
    version="0.3.4",
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
usage: tlsverify [-h] -H HOST [-p PORT] [-c CAFILES] [-C CLIENT_PEM] [-t TMP_PATH_PREFIX] [--disable-sni] [-b] [-v]
               [-vv] [-vvv] [-vvvv]

positional arguments:
  targets               All unnamed arguments are hosts (and ports) targets to test. ~$ tlsverify google.com:443
                        github.io owasp.org:80
optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  host to check
  -p PORT, --port PORT  TLS port of host
  -c CAFILES, --cafiles CAFILES
                        path to PEM encoded CA bundle file, url or file path accepted
  -C CLIENT_PEM, --client-pem CLIENT_PEM
                        path to PEM encoded client certificate, url or file path accepted
  -t TMP_PATH_PREFIX, --tmp-path-prefix TMP_PATH_PREFIX
                        local file path to use as a prefix when saving temporary files such as those being fetched
                        for client authorization
  --disable-sni         Do not negotiate SNI using INDA encoded host
  -b, --progress-bars   Show task progress bars
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
  - ✓ Negotiated protocol
  - ✓ Negotiated cipher (if a strong cipher, and if Forward Anonymity)
  - ✓ RSA private key
  - ✓ DSA private key
  - ✓ Compression supported
  - ✓ Client Renegotiation supported
  - ✓ Session Resumption caching
  - ✓ Session Resumption tickets
  - ✓ Session Resumption ticket hint
- HTTP Information
  - ✓ HTTP/1 supported (response status and headers)
  - ✓ HTTP/1.1 supported (response status and headers)
  - ✓ HTTP/2 (TLS) supported (response frame)
  - ✓ HTTP/2 clear text supported (response frame)
  - ✓ Expect-CT header (report_uri)
  - ✓ Strict-Transport-Security (HSTS) header
  - ✓ X-Frame-Options (XFO) header
  - ✓ X-Content-Type-Options header (nosniff)
  - ✓ Content-Security-Policy (CSP) header is present
  - ✓ Cross-Origin-Embedder-Policy (COEP) header (require-corp)
  - ✓ Cross-Origin-Resource-Policy (CORP) header (same-origin)
  - ✓ Cross-Origin-Opener-Policy (COOP) header (same-origin)
  - ✓ Referrer-Policy header (report on unsafe-url usage)
  - ✓ X-XSS-Protection header (enabled in blocking mode)
- X.509 Information
  - ✓ Root CA
  - ✓ Intermediate CAs
  - ✓ Certificate is self signed
  - ✓ Issuer
  - ✓ Serial Number (Hex, Decimal)
  - ✓ Certificate Pin (sha256)
  - ✓ Signature Algorithm
  - ✓ Fingerprint (md5, sha1, sha256)
  - ✓ SNI Support
  - ✓ OCSP response status
  - ✓ OCSP last status and time
  - ✓ OCSP stapling
  - ✓ OCSP must staple flag
  - ✓ Public Key type
  - ✓ Public Key size
  - ✓ Derive Private Key (PEM format)
  - ✓ Authority Key Identifier
  - ✓ Subject Key Identifier
  - ✓ TLS Extensions
  - ✓ Client Authentication expected
  - ✓ Certificate Issuer validation Type (DV, EV, OV)
- Hostname match
  - ✓ common name
  - ✓ subjectAltName
  - ✓ properly handle wildcard names
  - ✓ properly handle SNI
- Validations (Actual validity per the RFCs, fail any should fail to establish TLS)
  - ✓ Expiry date is future dated
  - ✓ OCSP revocation
  - ✓ Valid for TLS use (digital signature)
  - ✓ Deprecated protocol
  - ✓ Common Name exists, and uses valid syntax
  - ✓ Root Certificate is a CA and in a trust store
  - ✓ Validate clientAuth expected subjects sent by server
  - ✓ Intermediate key usages are verified
  - ✓ Valid SAN
  - ✓ Impersonation detections
  - ✓ C2 (command and control) detections
  - ✓ Non-production grade detections
  - ✓ issuerAlternativeName
  - ✓ authorityKeyIdentifier matches issuer subjectKeyIdentifier
  - ✓ keyUsage
  - ✓ extendedKeyUsage
  - ✓ inhibitAnyPolicy
  - ✓ basicConstraints path length
- Assertions (Opinionated checking, TLS is expected to still work)
  - ✓ Every certificate in the chain perform all validations (a requirement for zero-trust)
  - ✓ Weak ciphers
  - ✓ Weak keys
  - ✓ Weak Signature Algorithm
  - ~~If OCSP stapling, ensure a response was received~~ Fix planned for 0.3.4
  - ✓ rfc6066; if OCSP must-staple flag is present the CA provides a valid response, i.e. resolve and validate not revoked
  - ✓ Server certificates should not be a CA
  - ✓ When client certificate presented, check cert usage permits clientAuth
  - ✓ Certificate is not self signed
- Authentication
  - ✓ clientAuth
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
        'rich==10.12.0',
        'hyperframe==6.0.1',
        'retry==0.9.2'
    ],
    entry_points = {
        'console_scripts': ['tlsverify=tlsverify.cli:cli'],
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    options={"bdist_wheel": {"universal": "1"}},
)
