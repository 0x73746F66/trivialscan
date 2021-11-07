# tls-verify

Because, no one wants to write several hundred lines of code for every project that uses micro-services, internal APIs, zero-trust, etc. where you probably should be doing more then just the basic built-in OpenSSL hostname and root trust store checks.

Package `tls-verify` provides a command-line tool `tlsverify` which contacts an SSL/TLS server and obtains some information on its configuration. It aims at providing equal or better functionality of Internet-based tools like [Qualys SSL Server Test](https://www.ssllabs.com/ssltest/) without the requirement of the target server being internet connected.

You can use `tlsverify` on your internal network or local computer, to test your servers while they are being developed. It is equally capable of reaching any other internet connected server also.

## [Change Log](./docs/z.change-log.md)

## Documentation

See [Documentation](./docs/0.index.md) section of this repository

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
  - ✓ Known compromised Certificates
- Authentication
  - ✓ clientAuth
- ✓ CLI output evaluation duration
- ✓ OpenSSL verify errors are actually evaluated and reported instead of either terminate connection or simply ignored (default approach most use VERIFY_NONE we actually let openssl do verification and keep the connection open anyway)

## I have paid for weak certs, what now?

Likely you can get a free Certificate Reissuance: [Debian keep a list](https://wiki.debian.org/SSLkeys#SSL_Certificate_Reissuance) of references that might help, otherwise contact your cert issuer and ask them to correct the problem for free.
