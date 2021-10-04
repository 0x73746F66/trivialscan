# tls-verify

Because, no one wants to write several hundred lines of code for every project that uses micro-services, internal APIs, zero-trust, etc. where you probably should be doing more then just the basic built-in OpenSSL hostname and root trust store checks.

## Basic Usage

`pip install -U tls-verify`

```py
import tlsverify

host = 'google.com'
is_valid, _ = tlsverify.verify(host)
print('\nValid ✓✓✓' if is_valid else '\nNot Valid. There where validation errors')
```

### Results

```py
import tlsverify

host = 'google.com'
is_valid, validators_list = tlsverify.verify(host)
assert is_valid
# Or inspect each result separately
if is_valid is False:
  for validator in validators_list:
    print(validator.metadata.certificate_subject)
    print(validator.metadata.certificate_serial_number)
    print(validator.certificate_valid)
    print(validator.certificate_chain_valid)
    print(validator.certificate_verify_messages)
    print(validator.certificate_chain_validation_result)
```

util.Metadata uses `dataclasses` for convenience:

```py
# dict of normalized metadata
from dataclasses import asdict
print(asdict(validator.metadata))
```

### Certificate Formats

```py
print(validator.cert_to_text())
# Access DER/ASN1 bytes
print(validator.der)
# Access PEM encoded bytes
print(validator.pem)
# Access cryptography.x509.Certificate
print(type(validator.certificate))
# Access OpenSSL.crypto.X509
print(type(validator.x509))
```

## Granular Usage

```py
from pathlib import Path
from tlsverify import Validator

pem = Path(os.path.join(os.path.dirname(__file__), "cert.pem")).read_bytes()
validator = Validator()
validator.init_pem(pem)
validator.extract_metadata()
if not validator.verify(host, port):
  print(validator.metadata.certificate_subject)
  print(validator.metadata.certificate_serial_number)
  print(validator.certificate_valid)
  print(validator.certificate_chain_valid)
  print(validator.certificate_verify_messages)
  print(validator.certificate_chain_validation_result)
```

### Retrieve Certificates Only

```py
from tlsverify.util import get_certificates
x509, x509_certificate_chain, _, _ = get_certificates(host)
```

### View Certificate in plan text

```py
from pathlib import Path
from tlsverify import Validator

pem = Path(os.path.join(os.path.dirname(__file__), "cert.der")).read_bytes()
validator = Validator()
validator.init_der(der)
print(validator.cert_to_text())
```

### Only Verify the Certificate Chain

```py
from tlsverify import Validator
from tlsverify.util import get_certificates

x509, x509_certificate_chain, _, _ = get_certificates(host)
validator = Validator()
validator.init_x509(x509)
validator.extract_metadata()
validator.verify_chain(Validator.convert_x509_to_PEM(x509_certificate_chain))
```

### Just get the KeyUsage and ExtendedKeyUsage as lists

You may wish to call the `certvalidator` library yourself, to save you a few hundred lines of code (when not using `tls-verify`) you can gather the key usage lists first:

```py
from pathlib import Path
from tlsverify import Validator
from tlsverify.util import gather_key_usages

host = 'google.com'
pem = Path(os.path.join(os.path.dirname(__file__), "cert.pem")).read_bytes()
validator = Validator()
validator.init_pem(pem)
_, key_usage, ext_key_usage = gather_key_usages(validator.certificate)
```

Then call the external library directly, as you would without `tls-verify` [per their docs](https://github.com/wbond/certvalidator/blob/master/docs/api.md):

```py
from certvalidator import CertificateValidator
validator = CertificateValidator(der, intermediate_certs=intermediate_certs)
validator.validate_usage(
    key_usage=set(key_usage),
    extended_key_usage=set(ext_key_usage),
)
```

### Check if a KeyUsage or ExtendedKeyUsage is present

```py
from pathlib import Path
from tlsverify import Validator
from tlsverify.util import check_usage

pem = Path(os.path.join(os.path.dirname(__file__), "cert.pem")).read_bytes()
validator = Validator()
validator.init_pem(pem)
print(check_usage(validator.certificate, 'digital_signature'))
print(check_usage(validator.certificate, 'clientAuth'))
```

### Get TLS Extensions dictionary

```py
from pathlib import Path
from tlsverify import Validator
from tlsverify.util import gather_key_usages

host = 'google.com'
pem = Path(os.path.join(os.path.dirname(__file__), "cert.pem")).read_bytes()
validator = Validator()
validator.init_pem(pem)
extensions, _, _ = gather_key_usages(validator.certificate)
```

### is_self_signed

```py
from pathlib import Path
from tlsverify import Validator
from tlsverify.util import is_self_signed

pem = Path(os.path.join(os.path.dirname(__file__), "cert.pem")).read_bytes()
validator = Validator()
validator.init_pem(pem)
print(is_self_signed(validator.certificate))
```

### get subjectAlternativeNames (SAN)

```py
from pathlib import Path
from tlsverify import Validator
from tlsverify.util import get_san

pem = Path(os.path.join(os.path.dirname(__file__), "cert.pem")).read_bytes()
validator = Validator()
validator.init_pem(pem)
print(get_san(validator.certificate))
```

### Validate the common name (incl. wildcard) against the server host name

```py
from pathlib import Path
from tlsverify import Validator
from tlsverify.util import validate_common_name

host = 'google.com'
pem = Path(os.path.join(os.path.dirname(__file__), "cert.pem")).read_bytes()
validator = Validator()
validator.init_pem(pem)
print(validate_common_name(validator.metadata.certificate_common_name, host))
```

### Validate host name (incl. wildcard SAN and common name)

```py
from pathlib import Path
from tlsverify import Validator
from tlsverify.util import match_hostname

host = 'google.com'
pem = Path(os.path.join(os.path.dirname(__file__), "cert.pem")).read_bytes()
validator = Validator()
validator.init_pem(pem)
print(match_hostname(host, validator.certificate))
```


## Use it as a cli:

Get [pipx](https://packaging.python.org/key_projects/#pipx) for [better python command line tool installs](https://packaging.python.org/guides/installing-stand-alone-command-line-tools/) and then `pipx install --python $(which python3.9) tls-verify`

```sh
tlsverify --help
```

produces:

```
usage: tlsverify [-h] -H HOST [-p PORT] [-c CAFILES] [--sni] [-v] [-vv] [-vvv] [-vvvv]

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  host to check
  -p PORT, --port PORT  TLS port of host
  -c CAFILES, --cafiles CAFILES
                        path to PEM encoded CA bundle file
  --sni                 Negotiate SNI via PyOpenSSL Connection set_tlsext_host_name and INDA encoded host
  -v, --errors-only     set logging level to ERROR (default CRITICAL)
  -vv, --warning        set logging level to WARNING (default CRITICAL)
  -vvv, --info          set logging level to INFO (default CRITICAL)
  -vvvv, --debug        set logging level to DEBUG (default CRITICAL)
```

## Implemented

- Certificate Formats
  - ✓ plaintext
  - ✓ PEM
  - ✓ ASN1/DER
  - ✓ pyOpenSSL object
  - ✓ python `cryptography` object
- TLS Information
  - ✓ negotiated_protocol
  - ✓ negotiated_cipher
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
  - ✓ keys
  - ✓ signature algorithm

## ⌛ Todo

- Test timings
- Handshake Simulations
- Enumerate Cipher Suites
- Known RSA/DSA private keys: https://www.hdm.io/tools/debian-openssl/
- Common DH primes and public server param (Ys) reuse
- ECDH public server param reuse
- TLS extensions
  - basicConstraints path_length
  - IssuingDistributionPoint
  - cRLDistributionPoints
  - signedCertificateTimestampList
  - OCSPNonce
- rfc6066; OCSP must resolve if not stapled, if must-staple flag is present the CA provides a valid response, i.e. validate not revoked
- Timestamps are valid using NTP
- Not using known weak "x"
  - protocol
  - cipher
- Not using a known vulnerable "x"
- compromised private keys (pwnedkeys.com to start)
- compromised intermediate certs;
  - Lenovo Superfish
  - Dell eDellRoot
  - Dell DSD Test Provider
- Non-trusted certs; bundled with development tools
  - burp
  - wireshark
  - webpack
  - preact-cli
  - charles
- Issuer match (If the server is owned or operated by you, a Zero-trust requirement)
- if CT expected (Zero-trust requirement), Certificate Transparency resolves
- if HPKP is still present and expected, validate per the policy
- report Extended Validation
- report DNS CAA
- report DNSSEC
- report Secure Renegotiation
- report Downgrade attack prevention
- report TLS compression
- report Forward Secrecy
- report ALPN
- report NPN
- report SPDY
- report Session resumption
- report HSTS
- report HTTP status code and banners

### Rationale

#### Why another python library

We have several existing options in Python;
- `pyOpenSSL` Python bindings for OpenSSL
- `certifi` is self-explanatory
- `cryptography` is a powerful tool that can be used for this purpose
- `certvalidator` was intended to be used for this exact purpose

To perform proper and complete TLS validation, one must actually write several hundred lines of Python to bring all of the above together. In fact `certvalidator` is the only method I found that can effectively validate the entire cert chain! There are bug reports for doing it in python bindings to OpenSSL and the `cryptography` library for so many years now that it seems it will never be implemented.

Given `certvalidator` provide us a solution to validate the entire cert chain, I was very disappointed to learn that the validator class required at least 200+ lines of code just to build the `key_usages` argument by enumerating the TLS extensions.

We need a simple tool that abstracts the repeatable steps, and the code bases of the above are not ideal (typical gate-keeping or procrastination in PRs and unnecessary py-golf - sorry if you're a fan of perl golf, it's not for me)

#### NPN

NPN was the TLS extension used to negotiate SPDY (and, in transition, HTTP/2). During the standardization process, NPN was replaced with ALPN, published as rfc7301 in July 2014. Chrome removed NPN and SPDY protocol.

Given the maker of SPDY and therefore the transitional TLS extension NPN has removed support from their Chrome browser, any server that supports both have a larger than needed attack surface, and technology not supported for many years can be quietly vulnerable, so obscure that any vulnerability reports about them will be treated as not in scope, nor will they get a CVE published because the CVE issuer is the same entity that decides if it is a bug or not.

Maybe vulnerabilities in SPDY or NPN will be disclosed via UVI (Cloud Security Alliance), but UVI is not yet mainstream and is mostly unheard of in security research communities as of late 2021.

#### HPKP

Because browsers no longer validated HPKP, It is common knowledge that attackers were able to abuse the browser security model.
> This only effected websites that did not have any use for HPKP

When an attacker gained access to your server by any means, they can (once you were already compromised) then modify the webserver HTTP response headers by including a HPKP policy when it was not expected. This made client browsers block the compromised website, resulting in legitimate visitors not being able to load your website at all.

Again, this only effected websites that **DID NOT HAVE** any use for HPKP, and were already compromised.

HPKP is a perfect example of a strict certificate policy, and when it is expected it acts as a near perfect security feature. This is also it's downfall. If a browser enforces HPKP it can be abused in rare and very specific scenarios where HPKP was not even used for the purposes it was designed. 

HPKP itself has no known vulnerabilities or common implementation flaws. Abused 'was' previously limited entirely to victims that explicitly do not use HPKP and the browsers themselves were tricked to block legitimate users from reaching your website.

Web browsers no longer enforce HPKP, they simply ignore HPKP entirely.

For this reason HPKP is still a fantastic solution for securing any TLS communication channel. The only barrier is an onus on you as an implementer of HPKP validation to make sane implementation decisions (which is precisely what you do whenever you implement anything, every time)

#### Extended Validation

Domain Validated (DV) Certificates may be growing in popularity since the browsers ceased showing the organization name along with a green padlock, but the visual change is not material to the security characteristic associated with Extended Validation (EV) Certificates. When the visual changes occurred the mainstream non-technical or the uneducated in cybersecurity masses all declared that EV Certificates are dead, but the reality and truth of the matter is EV Certificates have never been more important.

Let's consider some facts:

1. DV Certificates are extensively (almost solely) used by malicious actors of all types; targeted, watering hole, spray-and-pray, any type leverage DV Certificates because they are free, trusted, and easily to obtain anonymously
2. A malicious EV Certificates is inherently forged for a target, displaying the forged organization name to a layman in the browser was an attack on the user trust; Only **"IF"** the layman was savvy enough they might not trust the forged cert. Today we hide the forgery and as a result there is automatic blind trust and no mechanism for a layman to see the forgery and potentially avoid the threat. To be concise, we used to offer a possible chance to thwart an attacker, now we simply force trust upon users and offer them no means to easily verify anymore. So the changes to EV Certificates in practice [made things worse, not better](https://webcache.googleusercontent.com/search?q=cache:s_bQ24QvDcQJ:https://par.nsf.gov/servlets/purl/10047386+&cd=6&hl=en&ct=clnk&gl=au).
3. Extended Validation certificates offer warranties up to $2M from my personal experience in Australia, When we are talking about a data breach like the one that happened to Equifax due to an expired EV CErtificate, it matters.
4. Legislative, Regulatory, International or Local Privacy Laws, Accreditation held for certain practices, Contractual Obligation (like PCI DSS) - all or any of these may obligate you to utilize at the least an EV Certificate, the DV Certificate has little (if any) security assurances.
5. The DV Certificate Issuers generally don't offer any additional features, therefore even if you attempt to use certain features like `ssl_stapling` it will simply be ignored. These Issuers, (pick on Let's Encrypt for this one) simply prefer low-barrier and ease-of-use over any and all security characteristics - so if they don't care, why would you put any trust in their DV Certificates to secure your TLS connections?
6. An EV Certificate inherently required an out-of-band validation, that is not automated like a DV Certificate. Therefore if an ATO (Account Take-over) or DNS hijacking attack were to be successful the attacker must be persistent and sometimes be physically attacking you. Which all takes significantly more time than the near-instant time it takes for the DV Certificates to be issued. When you operate public hosted (cloud) servers, they are typically ephemeral IP Addresses. The hazard with an IP Address that changes between distinct users is there is a possibility a patient malicious actor may get assigned an IP Address previously held by a valuable customer of the service provider. The way DNS works with TTL and caches means that some requests will still attempt to connect to IP Address you now have that were intended for the previous IP Address owner. If the IP Address the malicious attacker is assigned is rDNS checked and the malicious actor doesn't find anything of value, they can easily discard the IP Address and simply request a new one over and over until they get an IP that is of value to them. This is called IP Churn, and [a paper describes how this technique](https://webcache.googleusercontent.com/search?q=cache:dQ4atOcEvWEJ:https://kevin.borgolte.me/files/pdf/ndss2018-cloud-strife.pdf+&cd=13&hl=en&ct=clnk&gl=au) that is an accepted "how things work" can be combined with DV Certificates that are also accepted as "how things work", combined allow for DNS hijacking. This is a proven attack, and the attack vectors with continue to work as long as service providers assign IP Addresses that are still fresh and DV certificates are automatically issued in nanoseconds.

Put simply, DV Certificates are favored by attackers and seeing one should make you skeptical, they're issued for ease-of-use and not for security purposes, and there is a trivial DNS take-over attack that can be used for targeting if sufficiently motivated. An EV Certificate is the distinct opposite, attackers avoid using them unless they are desperate and motivated to ignore the risks to them, they are issues with security focus in spite of the time do validation which is an effective mitigation to the trivial DNS take-over attack.

#### Zero-trust

There are far too many claims of network security vendors who claim they apply a zero-trust architecture, but have complete and blind trust in their certificates. While this is extremely negligent, I cannot blame them for not doing proper validation when there are next to no codified example of how one actually performs proper and complete TLS verification.

With an absence of any open source, lack of easy path for vendors to do proper TLS verification, and not even the continued pressure we put on them to get this stuff right - none are actually attempting to properly apply zero-trust even if they market and claim they do, every single one of them that use certificates either have blind trust or are not even placed in a position in the technology stack to be informed to do proper validation anyway.

In the absence of vendors providing proper and complete TLS validation capabilities, the onus really is on the client to perform their own validation to protect themselves, no one will do it for you.

## Non-goals

Rewrite logic that is provided via existing packages int he ecosystem, currently we utilise:
- `pyOpenSSL` Python bindings for OpenSSL
- `certifi` is self-explanatory
- `cryptography` is a powerful tool that can be used for this purpose
- `certvalidator` was intended to be used for this exact purpose [but is limited](https://github.com/wbond/certvalidator/issues/36)

## I have paid for weak certs, what now?

Likely you can get a free Certificate Reissuance: [Debian keep a list](https://wiki.debian.org/SSLkeys#SSL_Certificate_Reissuance) of references that might help, otherwise contact your cert issuer and ask them to correct the problem for free.
