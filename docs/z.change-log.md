# Change Log

## 0.4.1 Oct 19th 2021

- timeout fix for some domains that do not respond (failure to connect) to SSL at all
- fixed the CAA validity by matching on organisation names in the issuer subject rather than the provided CAA dns record, this required adapting a [ccadb.org mapping](https://www.ccadb.org/resources) of known CAA identifiers
- completed the reference message when ValidationError is raised byt he cli

## 0.4.0 Oct 19th 2021

- Added `util.get_dnssec()` and `util.dnssec_valid()` for DNSSEC existence and validation
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
