# tls-verify

Because, no one wants to write several hundred lines of code for every project that uses micro-services, internal APIs, zero-trust, etc. where you probably should be doing more then just the basic built-in OpenSSL hostname and root trust store checks.

## Usage

Basic usage

```py
from tlsverify import Validator
host = 'expired.badssl.com'
validator = Validator(host)
if not validator.verify():
  print(validator.certificate_verify_messages)
  print(validator.certificate_chain_validation_result)

# Or inspect each result separately
print(validator.certificate_valid is True)
print(validator.certificate_chain_valid is True)
# dict of normalized metadata
print(validator.get_metadata())
# Access DER/ASN1
print(validator.der)
# Access cryptography.x509.Certificate
print(type(validator.certificate))
# Access OpenSSL.crypto.X509
print(type(validator.x509))
```

## Project Goals

1. ensure default and expected standard validation mechanism:
- ✓ Hostname match
  - ✓ common name
  - ✓ subjectAltName
  - ✓ properly handle wildcard names
- ✓ Root Certificate is a CA and in a trust store
- ✓ Expiry date is future dated compared to the computer time (not the actual time in reality)

2. ⌛ Enumerate the TLS extensions to ensure all validations are performed (excluding non-standard or any custom extensions that may exist)

3. Validate the complete chain (a requirement for zero-trust)
- ✓ build the chain for the user
- ✓ optionally; allow the user to include additional cacert bundle
- ⌛ optionally; cert chain is exactly 3 (Root CA, signer/issuer, server cert)

4. ✓ All certs in the chain are not revoked
- ✓ OCSP, must resolve if not stapled, if must-staple (rfc6066) is present the CA provides a valid response, i.e. validate not revoked
- ⌛ CRL, must resolve and not be revoked

5. ✓ Key usages for all certs in the chain are verified for correctness

6. ✓ Timestamps are valid
- ⌛ optionally: use NTP
- ✓ all certs Expiry date is future dated compared to the real time (NTP)
- ✓ all certs Issued date is past dated compared to the real time (NTP)

7. ✓ Not using known weak "x"
- ✓ keys
- ⌛ protocol
- ✓ signature algorithm
- ⌛ cipher

8. ⌛ Not using a known vulnerable "x"
- ⌛ compromised private keys (pwnedkeys.com to start)
- ⌛ compromised intermediate certs;
  - ⌛ Lenovo Superfish
  - ⌛ Dell eDellRoot
  - ⌛ Dell DSD Test Provider
- ⌛ certs bundled with development tools; 
  - ⌛ burp
  - ⌛ wireshark
  - ⌛ webpack
  - ⌛ preact-cli
  - ⌛ charles

all have known certs and should be rejected in production environments.

9. ⌛ Provide a simple set of methods that can verify the following:
- ⌛ Issuer match
  - ⌛ If the server is owned or operated by you (Zero-trust requirement)
- ⌛ if CT expected (Zero-trust requirement), Certificate Transparency resolves
- ⌛ if HPKP is still present and expected, validate per the policy

### Rationale

#### Why another python library

We have several existing options in Python;
- Python bindings for OpenSSL are built-in
- `certifi` is self-explanatory
- `cryptography` is a powerful tool that can be used for this purpose
- `certvalidator` was intended to be used for this exact purpose

To perform proper and complete TLS validation, one must actually write several hundred lines of Python to bring all of the above together. In fact `certvalidator` is the only method I found that can effectively validate the entire cert chain! There are bug reports for doing it in python bindings to OpenSSL and the `cryptography` library for so many years now that it seems it will never be implemented.

Given `certvalidator` provide us a solution to validate the entire cert chain, I was very disappointed to learn that the validator class required at least 200+ lines of code just to build the `key_usages` argument by enumerating the TLS extensions.

We need a simple tool that abstracts the repeatable steps, and the code bases of the above are not ideal (typical gate-keeping or procrastination in PRs and unnecessary py-golf - sorry if you're a fan of perl golf, it's not for me)

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

