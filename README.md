# tls-verify

Because, no one wants to write several hundred lines of code for every project that uses micro-services, internal APIs, zero-trust, etc. where you probably should be doing more then just the basic built-in OpenSSL hostname and root trust store checks.

# [Change Log](./docs/z.change-log.md)

# Documentation

See [Documentation](./docs/0.index.md) section of this repository

## Implemented

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
  - ✓ rfc6066; if OCSP must-staple flag is present the CA provides a valid response, i.e. resolve and validate not revoked
  - ✓ Server certificates should not be a CA
  - ✓ When client certificate presented, check cert usage permits clientAuth
  - ✓ Certificate is not self signed
- Authentication
  - ✓ clientAuth
- ✓ CLI output evaluation duration
- ✓ OpenSSL verify errors are actually evaluated and reported instead of either terminate connection or simply ignored (default approach most use VERIFY_NONE we actually let openssl do verification and keep the connection open anyway)

## Impersonation detections

These are commonly used for phishing sites that are quickly deployed and are made to look like a trusted site. These are HTTPS/TLS sites and since browsers no longer show the green padlock it is harder for the layman to visually identify any problems (specifically if the domain name is visually a perfect match due to hidden and look-alike characters or other top level domains e.g. the company named "post" is `post.com` and see `post.express` and these new suffix are sso common that we are not surprised to see them so phishing sites are all too common).

Quick note about these webserver tools; all have 1 thing in common, they offer a default HTTPS/TLS capability but all are configurable by advanced users to perform alternative behaviors to the following defaults. Detecting the indicators of default behaviors is effective in most cases but a determined attacker will likely have compromised an authentic certificate authority or certificate signer to evade detection - as has been reported in media previously many times.

**preact-cli** Is a popular tool to quickly serve HTTPS sites using a shared TLS, it can be identified using the SAN `lvh.me`

**webpack** Same as above

**sirv** Same as above

## C2 (command and control) detections

Many hacking tools (used by both ethical and malicious actors) well serve a website that communicates over HTTPS/TLS, and these tools have default behaviors and indicators that we can detect on the HTTPS/TLS layer.

**Metasploit’s Meterpreter Reverse HTTP Module**
tls-verify has default resilience to this hacking tool. The certificates used by this tool aren't signed by a trusted CA and the domain names are random (i.e. fail hostname matching)

**PortSwigger Burp** All certificates generated by Burp are issued using a CA with the subject `C=PortSwigger, ST=PortSwigger, L=PortSwigger, O=PortSwigger, OU=PortSwigger CA, CN=PortSwigger CA`

Honorary mention; **Wireshark**. All TLS traffic that passes through this tool and read (decrypted) is unchanged and will arrive on the endpoint with no integrity compromises, therefore the use of Wireshark is undetectable and has no side effects. Wireshark takes a copy of the packets and allows them to continue on their way as-is, the copies are inspected by Wireshark, not the actual packets the endpoint receives. This is how TLS is intended to work, it provides you integrity only, not confidentiality or privacy (Don't believe everything Apple tells you on billboards and fancy ads)

## Non-production grade detections

Other tools with shared certificates that should not be used for a production web server using TLS

**Charles Proxy SSL Proxying** The [legacy CA](https://www.charlesproxy.com/assets/legacy-ssl/ssl.zip?k=1fc84b5ab6) stopped working with version 3.10 and the new technique uses a predictable-random CN. All have the `OU=https://charlesproxy.com/ssl` in common.

## ⌛ Todo

- Handshake Simulations
- More impersonation detections
- More C2 (command and control) detections
- If OCSP stapling, ensure a response was received
- Known RSA/DSA private keys: https://www.hdm.io/tools/debian-openssl/
- Common DH primes and public server param (Ys) reuse - logjam
- ECDH public server param reuse - Racoon
- TLS extensions
  - IssuingDistributionPoint
  - cRLDistributionPoints
  - signedCertificateTimestampList (CT)
  - OCSPNonce reuse
- Timestamps are valid using NTP
- compromised private keys (pwnedkeys.com to start)
- compromised intermediate certs;
  - Lenovo Superfish
  - Dell eDellRoot
  - Dell DSD Test Provider
- Non-trusted certs; bundled with development tools
  - webpack
  - preact-cli
  - charles
- Issuer match (If the server is owned or operated by you, a Zero-trust requirement)
- if CT expected (Zero-trust requirement), Certificate Transparency resolves
- if HPKP is still present and expected, validate per the policy
- Proxy support
- Authentication
  - proxy auth
  - basic authentication
  - apikey
  - custom authenticator (i.e. bespoke signers and custom headers
  - HMAC [httpbis-message-signatures](https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/) example custom authenticator
- report DNS CAA
- report DNSSEC
- report Downgrade attack prevention

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
