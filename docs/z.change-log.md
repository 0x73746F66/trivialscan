# Change Log

## 1.1.3 Dec 2nd 2021

- bump `tlstrust==2.0.3` for more android version support
- updated repo paths

## 1.1.2 Dec 2nd 2021

- renamed `certificate_pin_sha256` to `certificate_spki_fingerprint`
- added pwnedkeys.com check

## 1.1.1 Nov 22nd 2021

- Bug fix for JSON output

## 1.1.0 Nov 22nd 2021

- `CertValidator` renamed to `LeafCertValidator`
- Added TLSA/DANE detection via `util.get_tlsa_answer()`
- Fixed HTTP/2 crashing when it encounters `ISO-8859-1` encoding
- Bug fixes for cases where common names in issuer and cert subjects are missing
- Fixed CAA check that failed due to missing common names in subjects
- Added `private algorithm` and `EC` algorithm for DNSSEC
- Fixed DNSSEC checks that failed due to unknown algorithms
- Added `util.get_extensions_by_oid()`
- Added `util.get_txt_answer()`

## 1.0.1 Nov 6th 2021

- Compliance checks no longer prevent displaying validation results when negotiating TLS fails

## 1.0.0 Nov 6th 2021

- Compliance checks no longer influence validation result
- Added cli option `--summary-only` to not include informational details, show only important validation outcomes
- Completed compromised certificate checking
- Moved constants in `tlsverify.util` to `tlsverify.constants`

## 0.4.15 Nov 1st 2021

- bump `tlstrust==2.0.1` for more android version support
- Android Trust Store status improved

## 0.4.14 Nov 1st 2021

- Added support for FIPS 140-2 transition to NIST SP800-131A assertions via `--fips-nist-transition-mode`
- Added support for NIST SP800-131A strict mode assertions via `--nist-strict-mode`
- Changed some CLI outputs to be more concise
- Bug fix for TLS version interference detection
- Bug fix for weak protocol detection

## 0.4.13 Oct 31st 2021

- Added PCI DSS 3.2.1 assertions via `--pci-dss` on the cli and `Validator.pcidss_compliant()`
  - CA Trust was validated
  - RSA and DSA keys are greater than 2048 bits
  - EC and DH keys are greater than 256 bits
  - Ciphers are at least 128 bits
  - Not supporting deprecated or weak protocols
  - Not supporting deprecated or weak algorithms
  - No known vulnerabilities, currently; compression, renegotiation, or session_resumption

## 0.4.11 Oct 30th 2021

- Added TLS long handshake intolerance detection

## 0.4.10 Oct 29th 2021

- Added `--json-file` cli argument
- Added `--show-private-key` cli argument
- Added `--hide-validation-details` cli argument
- Renamed `'-b', '--progress-bars'` to `--hide-progress-bars` cli argument which will show progress bars by default

## 0.4.9 Oct 29th 2021

- Bump `tlstrust==2.0.0` for AKI to reduce false positives matches and false negative missing certs
- Do not duplicate intermediate CA certs in the chain when teh server attempts to send a root CA, ignore the server cert and use the trust store copy only

## 0.4.8 Oct 29th 2021

- Added `Metadata.certificate_version`
- Added `Metadata.certificate_expired` as a boolean to save computing of `notBefore`
- Added `Metadata.tls_version_interference`
- Added `Metadata.tls_version_interference_versions`
- Added tls version interference tests and validation messages
- Improved code quality of progress bars
- Improved code quality of `Transport.connect_least_secure`, `Validator.extract_x509_metadata`, and `CertValidator.verify_chain`

## 0.4.7 Oct 27th 2021

- Bump `tlstrust==1.1.1` to show a more verbose platform trust store version

## 0.4.6 Oct 27th 2021

- Documentation updates

## 0.4.5 Oct 27th 2021

- Fixed a DNSSEC validation bug on subdomains
- Report DNSSEC algorithm and raise validation errors for weak algorithms
- Fixed a CAA validation bug on subdomains
- Made all messages reporting 'days ago' or similar messages consistently 'inclusive' days
- Deprecated `util.get_dnssec` which is renamed to `util.get_dnssec_answer()` for clarity
- Deprecated `Transport.test_highest_tls_version()` which is replaced by `Transport.test_tls_version()`
- Added output showing if SCSV was derived
- Added server preferred tls protocol, via new `Transport.test_tls_version()`
- Show validation messages for TLS downgrade availability, but not treat as a TLS verification error
- Fixed http_status_code to not always be `0`
- Better messages for 'known weak X' findings
- Added optional socket argument to `util.prepare_connection()`, when omitted previous functionality will mean it gets created for you
- Refactored cli outputs for more granular control over word choice and color of boolean and null results
- CLI now uses human readable text rather than code key names
- Included verbose validation messages
- Ignore unnecessary OpenSSL `WantRead` warnings via `util.do_handshake()` showing at `-vv` verbosity level that are expected and not actually errors for our purposes
- List all offered TLS versions
- Derive TLS version intolerance, and list the versions attempted by the client that did not negotiate the server supported version
- Added arguments `max_retries` and `counter` to `util.is_connection_closed()` to handle infinity `SSL.WantReadError`

## 0.4.4 Oct 26th 2021

- Cache `Transport` for unit tests

## 0.4.3 Oct 23rd 2021

- Bump `tlstrust==1.1.0` which optionally uses SKI for Root CA matching in case Certificates aren't issued improperly, using non-unique Issuer Subject Common Name
- Show platform version information on cli `--version`
- Simplified code for cli output, and reduced code reuse, with no functional changes

## 0.4.2 Oct 23rd 2021

- Added Mozilla CRLite Revocation
- Added `tlstrust` library to verify Root CA Trust Stores (starting with 6 stores; Apple legacy, Android, Java, Linux, CCADB, and Python)
- Root CA is added to the chain and validated like any other certificate (though browsers ignore this, it is a TLS requirement)
- Show `tls-verify` version on cli `--version`
- Bug fix to avoid fatal errors and just show output we have for sites that don't fully negotiate TLS

## 0.4.1 Oct 19th 2021

- timeout fix for some domains that do not respond (failure to connect) to SSL at all
- fixed the CAA validity by matching on organisation names in the issuer subject rather than the provided CAA dns record, this required adapting a [ccadb.org mapping](https://www.ccadb.org/resources) of known CAA identifiers
- completed the reference message when ValidationError is raised byt he cli

## 0.4.0 Oct 19th 2021

- Added `util.get_dnssec_answer()` and `util.dnssec_valid()` for DNSSEC existence and validation
- Added `util.get_caa()`, `util.caa_exist()`, and `util.caa_valid()` for CAA record existence and validation

## 0.3.7 Oct 18th 2021

- Added code to manually resolve OCSP for verification (verify status codes from OpenSSL were never evaluated)
- fixed CLI output colored results for some TLS extensions

## 0.3.6 yanked

## 0.3.5 Oct 17th 2021

- CLI output Results are now colored

## 0.3.4 Oct 16th 2021

- CLI now supports assessing multiple target domains
- Added reference certificates and utility tool to view them

## 0.3.3 Oct 15th 2021

- added detections for possible phish or malicious

## 0.3.2 Oct 14th 2021

- Fixed an issue with the h2c test that effected some sites that sink non-TLS requests
- Adjusted CLI output frame title and captions

## 0.3.1 Oct 14th 2021

- Added http2 cleartext (h2c) support
- Made `Validator` a base class and split into `CertValidator` and `PeerCertValidator` for respective purposes
- Output properly identify certificate types as one of; Server, Intermediate, Intermediate CA, or Root CA
- Adjust outputs based on certificate type
- removed bespoke path_length basicConstraint checking from `CertValidator.verify_chain()`, instead rely on external lib `CertificateValidator` to identify broken paths
- Added `util.get_certificate_extensions()` which returns extensions as a list of dictionaries
- Added `util.get_valid_certificate_extensions()` which returns only valid extension classes in a list
- `util.gather_key_usages()` no longer returns extensions, use one of the new methods instead
- Added `util.get_ski_aki()` to unify multiple places that needed this
- unified peer validator implementations across cli and `verify` helper

## 0.3.0 Oct 13th 2021

- Improved cli outputs
- Renamed cli argument `--sni` to `--disable-sni`
- Added cli argument to enable progress bars
- Simplified `tlsverify.verify` helper function
- New `Transport` class `tlsverify.transport.Transport` for all transport related functionality
- Moved `Metadata` class from `tlsverify.util.Metadata` to `tlsverify.metadata.Metadata`
- Moved `Validator` class from `tlsverify.Validator` to `tlsverify.validator.Validator`
- Validator class refactored to remove all transport related functionality, it now mounts a `Transport` instance for validation purposes
- Removed `Validator.extract_metadata`, which is now split into; `extract_x509_metadata` and `extract_transport_metadata` and called privately when needed
- Removed `Validator.client_authentication` which is not part of the `Transport` class
- Added the OID to derive EV, DV, OV certs
- Added OCSP resolution and response statuses
- Added detections for Session Resumption caching and tickets
- Infer weak ciphers by checking against a list of ciphers considered safe from known attacks, with available empirical proof
- Infer strong ciphers, i.e. the 3 TLS1.3 ciphers that have no known weaknesses, everything else is not considered 'strong' (but may not be vulnerable either)
- `util.filter_valid_files_urls` now returns `False` instead of raising exceptions
- Removed `util.get_server_expected_client_subjects` and `util.get_certificates` (Refactored to the `Transport` class)
- Infer compression support
- Infer client-side TLS Renegotiation support
- Validate basicConstraints path length (i.e. Let's Encrypt serial `0x912b084acf0c18a753f6d62e25a75f5a` uses this constraint and some issued certificates had invalid chains)
- Added HTTP Information:
  - HTTP/1 supported (response status and headers)
  - HTTP/1.1 supported (response status and headers)
  - HTTP/2 (TLS) supported (response frame)
  - Expect-CT header (report_uri)
  - Strict-Transport-Security (HSTS) header
  - X-Frame-Options (XFO) header
  - X-Content-Type-Options header (nosniff)
  - Content-Security-Policy (CSP) header is present
  - Cross-Origin-Embedder-Policy (COEP) header (require-corp)
  - Cross-Origin-Resource-Policy (CORP) header (same-origin)
  - Cross-Origin-Opener-Policy (COOP) header (same-origin)
  - Referrer-Policy header (report on unsafe-url usage)
  - X-XSS-Protection header (enabled in blocking mode)
- Added X.509 Information:
  - Root CA
  - Intermediate CAs
  - OCSP response status
  - OCSP last status and time
  - OCSP stapling
  - OCSP must staple flag (rfc6066)
  - Derive Private Key (PEM format)
  - Client Authentication expected
  - Certificate Issuer validation Type (DV, EV, OV)

## 0.2.3 Oct 7th 2021

- Added pypi.org page documentation
- Fixed OpenSSL errors to be correct messages

## 0.2.2 Oct 7th 2021

- Added `util` documentation
- Added documentation for all known errors and validation failures
- Organized internal exceptions

## 0.2.1 Oct 7th 2021

- Added structured documentation
- fingerprints now match the browser format when output on cli
- moved static methods from `Validator` to the `util` module
- dropped redundant `host` and `port` from `Validator.verify()` for simplicity

## 0.2.0 Oct 7th 2021

- Completed the `clientAuth` implementation, which broke backwards compatibility.
- All OpenSSL validations are now performed and captured (instead of ignored and re-implemented like other libraries are doing).

## 0.1.7 Oct 5th 2021

Fixed some bugs and added some `clientAuth` functions without breaking backwards compatibility.
This release is usable for a more thorough verification TLS than anything else I've compared to so far.

## 0.1.1 Oct 4th 2021

Initial public release which may be of little use, please upgrade ASAP
