from setuptools import setup, find_packages

setup(
    name="tls-verify",
    version="1.1.5",
    author='Christopher Langton',
    author_email='chris@langton.cloud',
    description="Validate the security of your TLS connections so that they deserve your trust.",
    long_description="""
# tls-verify

Validate the security of your TLS connections so that they deserve your trust.

## [Documentation](https://gitlab.com/trivialsec/tlsverify/-/blob/main/docs/0.index.md)

![Leaf cba.com.au](https://gitlab.com/trivialsec/tlsverify/-/raw/main/docs/images/leaf-cba.com.au.png)

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
usage: tlsverify [-h] [-H HOST] [-p PORT] [-c CAFILES] [-C CLIENT_PEM] [-t TMP_PATH_PREFIX] [--pci-dss] [--nist-strict-mode] [--fips-nist-transition-mode] [--disable-sni]
               [--show-private-key] [-s] [--hide-validation-details] [-j JSON_FILE] [--hide-progress-bars] [-v] [-vv] [-vvv] [-vvvv] [--version]
               [targets ...]

positional arguments:
  targets               All unnamed arguments are hosts (and ports) targets to test. ~$ tlsverify google.com:443 github.io owasp.org:80

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  single host to check
  -p PORT, --port PORT  TLS port of host
  -c CAFILES, --cafiles CAFILES
                        path to PEM encoded CA bundle file, url or file path accepted
  -C CLIENT_PEM, --client-pem CLIENT_PEM
                        path to PEM encoded client certificate, url or file path accepted
  -t TMP_PATH_PREFIX, --tmp-path-prefix TMP_PATH_PREFIX
                        local file path to use as a prefix when saving temporary files such as those being fetched for client authorization
  --pci-dss             Include PCI DSS requirements assertions
  --nist-strict-mode    Include NIST SP800-131A strict mode assertions
  --fips-nist-transition-mode
                        Include FIPS 140-2 transition to NIST SP800-131A assertions
  --disable-sni         Do not negotiate SNI using INDA encoded host
  --show-private-key    If the private key is exposed, show it in the results
  -s, --summary-only    Do not include informational details, show only validation outcomes
  --hide-validation-details
                        Do not include detailed validation messages in output
  -j JSON_FILE, --json-file JSON_FILE
                        Store to file as JSON
  --hide-progress-bars  Hide task progress bars
  -v, --errors-only     set logging level to ERROR (default CRITICAL)
  -vv, --warning        set logging level to WARNING (default CRITICAL)
  -vvv, --info          set logging level to INFO (default CRITICAL)
  -vvvv, --debug        set logging level to DEBUG (default CRITICAL)
  --version
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
  - ✓ RSA private key
  - ✓ DSA private key
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
  - ✓ Derive Private Key (PEM format)
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

## [Change Log](https://gitlab.com/trivialsec/tlsverify/-/blob/main/docs/z.change-log.md)
    """,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/trivialsec/py-tls-veryify",
    project_urls={
        "Source": "https://gitlab.com/trivialsec/tlsverify",
        "Documentation": "https://gitlab.com/trivialsec/tlsverify/-/blob/main/docs/0.index.md",
        "Tracker": "https://gitlab.com/trivialsec/tlsverify/-/issues",
    },
    classifiers=[
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
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
        'retry==0.9.2',
        'urllib3==1.26.7',
        'requests==2.26.0',
        'dnspython==2.1.0',
        'tldextract==3.1.2',
        'moz-crlite-query==0.4.2',
        'tlstrust==2.0.4'
    ],
    entry_points = {
        'console_scripts': ['tlsverify=tlsverify.cli:cli'],
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    options={"bdist_wheel": {"universal": "1"}},
)
