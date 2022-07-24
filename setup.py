import distutils.text_file
import distutils.spawn
from io import StringIO
from pathlib import Path
from setuptools import setup, find_packages

__version__ = "3.0.0"

try:
    install_requires = distutils.text_file.TextFile(filename=str(
        Path(__file__).with_name('requirements.txt'))).readlines()
except FileNotFoundError:
    install_requires = distutils.text_file.TextFile(file=StringIO("""
cryptography>=2.0
certifi
asn1crypto
pyOpenSSL
rich
validators
idna
tlstrust==2.6.4
certvalidator
dnspython
h2==4.1.0
hpack==4.0.0
moz-crlite-query
oscrypto
requests==2.27.1
urllib3==1.26.9
appdirs==1.4.4
attrs==21.4.0
cattrs==1.10.0
requests-cache==0.9.4
url-normalize==1.4.3
retry
tldextract
pyyaml
art
keyring==23.6.0
deepdiff
pycryptodome==3.15.0
beautifulsoup4==4.11.1""")).readlines()


setup(
    name="trivialscan",
    version=__version__,
    author='Christopher Langton',
    author_email='chris@trivialsec.com',
    description="Validate the security of your TLS connections so that they deserve your trust.",
    url="https://gitlab.com/trivialsec/trivialscan",
    project_urls={
        "Source": "https://gitlab.com/trivialsec/trivialscan",
        "Documentation": "https://gitlab.com/trivialsec/trivialscan/-/blob/main/docs/0.index.md",
        "Tracker": "https://gitlab.com/trivialsec/trivialscan/-/issues",
    },
    classifiers=[
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    zip_safe=False,
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'console_scripts': ['trivial=trivialscan.cli.__main__:main'],
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    options={"bdist_wheel": {"universal": "1"}},
    long_description="""
# Trivial Scanner

Validate the security of your TLS connections so that they deserve your trust.

## [Documentation](https://gitlab.com/trivialsec/trivialscan/-/blob/main/docs/0.index.md)

Summary CLI output

![trivialscan summary](https://gitlab.com/trivialsec/trivialscan/-/raw/main/docs/images/trivialscan-summary.jpg)

Security Score Card

![trivialscan score-card](https://gitlab.com/trivialsec/trivialscan/-/raw/main/docs/images/trivialscan-score-card.jpg)

For full CLI output and JSON format please look in `examples/` of the Gitlab repository

## Basic Usage

`python3 -m pip install -U trivialscan`

```py
import trivialscan

transport, evaluations = trivialscan.tlsprobe(
    hostname="ssllabs.com",
    port=443,
)
is_valid = trivialscan.is_valid(transport.store)
print('Valid ✓✓✓' if is_valid else 'Not Valid !!!')
```

`python3 -m pip install pipx && pipx install trivialscan`

On the command-line:

```sh
trivial scan --help
```

## Features

- Compliance
  - PCI DSS 3.2.1
  - NIST SP800-131A (strict mode)
  - FIPS 140-2 (NIST SP800-131A transition mode)
- Certificate Formats
  - ✓ plaintext
  - ✓ PEM
  - ✓ ASN1/DER
  - ✓ pyOpenSSL object
  - ✓ python `cryptography` object
- TLS Information
  - ✓ Negotiated protocol
  - ✓ Negotiated cipher (if a strong cipher, and if Forward Anonymity)
  - ✓ List all offered TLS versions
  - ✓ Server preferred protocol
  - ✓ Compression supported
  - ✓ Client Renegotiation supported
  - ✓ Session Resumption caching
  - ✓ Session Resumption tickets
  - ✓ Session Resumption ticket hint
  - ✓ Downgrade attack detection and SCSV
  - ✓ TLS version intolerance
  - ✓ TLS version interference
  - ✓ TLS long handshake intolerance detection
  - ✓ TLSA/DANE detection
- DNS Information
  - ✓ Certification Authority Authorization (CAA) present
  - ✓ CAA Valid
  - ✓ DNSSEC present
  - ✓ DNSSEC valid
  - ✓ DNSSEC algorithm
  - ✓ DNSSEC deprecated and weak algorithms
- HTTP Information
  - ✓ HTTP/1 supported (response status and headers)
  - ✓ HTTP/1.1 supported (response status and headers)
  - ✓ HTTP/2 (TLS) supported (response frame)
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
  - ✓ Expired
  - ✓ Version
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
  - ✓ Authority Key Identifier
  - ✓ Subject Key Identifier
  - ✓ TLS Extensions
  - ✓ Client Authentication expected
  - ✓ Certificate Issuer validation Type (DV, EV, OV)
  - ✓ Root CA Trust Stores
- Hostname match
  - ✓ common name
  - ✓ subjectAltName
  - ✓ properly handle wildcard names
  - ✓ properly handle SNI
- Validations (Actual validity per the RFCs, fail any should fail to establish TLS)
  - ✓ Expiry date is future dated
  - ✓ OCSP revocation
  - ✓ Mozilla CRLite Revocation
  - ✓ Valid for TLS use (digital signature)
  - ✓ Deprecated protocol
  - ✓ Common Name exists, and uses valid syntax
  - ✓ Root Certificate is a CA and in a trust store
    - ✓ Real Root CA Trust Stores; specific evaluations of trust that actually exist today (unlike Qualys and others who use 1990-2000s stores)
    - ✓ Platform specific evaluations of trust
    - ✓ Evaluations of trust for Web Browsers
    - ✓ Programming Language specific Trust (for Microservice architecture and APIs)
    - ✓ Python libraries Trust
    - ✓ Go modules Trust
    - ✓ Rust crates Trust
    - ✓ Erlang libraries Trust
    - ✓ Node.js libraries Trust
    - ✓ Ruby gem Trust
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
  - ✓ Root CA is added to the chain and validated like any other certificate (though browsers ignore this, it is a TLS requirement)
- Assertions (Opinionated checking, TLS is expected to still work)
  - ✓ Valid CAA
  - ✓ Valid DNSSEC
  - ✓ Every certificate in the chain perform all validations (a requirement for zero-trust)
  - ✓ Weak ciphers
  - ✓ Weak keys
  - ✓ Weak Signature Algorithm
  - ✓ rfc6066; if OCSP must-staple flag is present the CA provides a valid response, i.e. resolve and validate not revoked
  - ✓ Server certificates should not be a CA
  - ✓ When client certificate presented, check cert usage permits clientAuth
  - ✓ Certificate is not self signed
  - ✓ Compromised Certificate
  - ✓ Compromised Private Key
- Authentication
  - ✓ clientAuth
- ✓ CLI output evaluation duration
- ✓ OpenSSL verify errors are actually evaluated and reported instead of either terminate connection or simply ignored (default approach most use VERIFY_NONE we actually let openssl do verification and keep the connection open anyway)

## [Change Log](https://gitlab.com/trivialsec/trivialscan/-/blob/main/docs/z.change-log.md)
    """,
    long_description_content_type="text/markdown",
)
