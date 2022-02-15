# Contributing

Releases
-----------

Follow SemVer:

- major releases are discussed with all maintainers and all deprecations in previous releases will be finalized
- minor releases should be backwards compatible so any deprecations must be indicated to end-users, and this may require a wrapper function for the deprecated function using the old name that holds the deprecation warning OR supporting both deprecated and new functionality using a flag for the new and default to the old
- patch releases must be completely backwards compatible, so only add functionality, do not delete anything. if a change is made consider minor release instead. Of course a patch may be used to restore broken functionality so ensure the broken version is yanked once patched

Merge Checklist
-----------

- Version bump in `setup.py` and `cli.py`
- Coverage `make test` remains same or better, never reduce coverage percentage
- All tests pass
- Check dependencies; ensure all are latest (with compatibility to other dependencies as the only exception)
- Run SAST `make test-local` and address all findings, exceptions will be part of the code review so be descriptive
- Update the README and `setup.py` features lists
- Update the docs
- Complete a change log entry

Project non-goals
-----------

One main rule here, no rewriting logic that is provided via existing packages in the ecosystem where possible, it is not hard to literally search the code Github and if it is compatible with the license, or better it is on PyPi, integrate it directly or fork it.

Currently we utilise:
- `pyOpenSSL` Python bindings for OpenSSL
- `certifi` is self-explanatory
- `cryptography` is a powerful tool that can be used for this purpose
- `certvalidator` was intended to be used for this exact purpose [but is limited](https://github.com/wbond/certvalidator/issues/36)

Less of a rule, just good advice. If the functionality you want to add is significantly large, complex, or niche - consider making it a separate library and then integrate it here. [tlstrust](https://pypi.org/project/tlstrust/) is an example where it was both large and complex enough to be best suited in it's own package but still fully integrated into this tool.

What to contribute?
-----------

Anything you want, or one of these:

⌛⌛ 3.0.0 Todo List ⌛⌛

- HSTS Preloading
- Handshake Simulations
- More impersonation detections
- More C2 (command and control) detections
- Known RSA/DSA private keys: https://www.hdm.io/tools/debian-openssl/
- Common DH primes and public server param (Ys) reuse - logjam
- ECDH public server param reuse - Racoon
- TLS extension intolerance
- TLS extensions
  - nameConstraints [oid 2.5.29.30](https://www.alvestrand.no/objectid/2.5.29.30.html) [rfc5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10) [ref1](https://netflixtechblog.com/bettertls-c9915cd255c0#8498) [ref2](https://docs.aws.amazon.com/acm-pca/latest/userguide/name_constraints.html)
  - signedCertificateTimestampList (CT)
  - OCSPNonce reuse
- Timestamps are valid using NTP
- Expected Issuer public key match (If the server is owned or operated by you, a Zero-trust requirement)
- if CT expected (Zero-trust requirement), Certificate Transparency resolves
- if HPKP is still present and expected, validate per the policy
- Scanner proxy support
- Scanner Authentication
  - proxy auth
  - custom authenticator (i.e. pass the request object to modify with bespoke signers, custom headers, query string params, etc.)
- Informational Outputs
  - Public Key Modulus
  - deep link https://crt.sh/?sha1=
  - Certificate Transparency
  - Trust Rating
  - Risk Score (A+ to F)
