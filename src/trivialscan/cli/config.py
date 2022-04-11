from trivialscan import validator, pci, nist, fips

CLI_COLOR_OK = 'dark_sea_green2'
CLI_COLOR_NOK = 'light_coral'
CLI_COLOR_ALERT = 'yellow3'
CLI_COLOR_NULL = 'magenta'
CLI_VALUE_TRUSTED = 'Trusted'
CLI_VALUE_NOT_TRUSTED = 'Not Trusted'
CLI_VALUE_VALID = 'Valid'
CLI_VALUE_NOT_VALID = 'Validation Errors'
CLI_VALUE_PASS = 'Pass'
CLI_VALUE_FAIL = 'Fail'
CLI_VALUE_YES = 'Yes'
CLI_VALUE_NO = 'No'
CLI_VALUE_DETECTED = 'Detected'
CLI_VALUE_PRESENT = 'Present'
CLI_VALUE_ABSENT = 'Absent'
CLI_VALUE_OK = 'OK'
CLI_VALUE_NOK = 'NOT OK'
CLI_VALUE_INEFFECTIVE = 'Ineffective'
CLI_VALUE_REVOKED = 'Revoked'
CLI_VALUE_NOT_REVOKED = 'Not Revoked'
CLI_VALUE_NA = 'N/A'
STYLES = {
    'certificate_valid': {'text': 'Certificate Valid', 'represent_as': (CLI_VALUE_VALID, CLI_VALUE_NOT_VALID), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'certificate_chain_valid': {'text': 'Certificate Chain Valid', 'represent_as': (CLI_VALUE_VALID, CLI_VALUE_NOT_VALID), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'certificate_chain_validation_result': {'text': 'Certificate Chain Validation Result'},
    validator.VALIDATION_CLIENT_AUTHENTICATION: {'text': 'Client Authentication', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_CLIENT_AUTH_USAGE: {'text': 'Provided client Certificate authentication usage', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_NOT_EXPIRED: {'text': 'Certificate is not expired', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_ISSUED_PAST_TENSE: {'text': 'Certificate issued in the past', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_SUBJECT_CN_DEFINED: {'text': 'Subject CN was defined', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_SUBJECT_CN_VALID: {'text': 'Subject CN has valid syntax', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_MATCH_HOSTNAME: {'text': 'Subject CN matches the server host name', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_NOT_SELF_SIGNED: {'text': 'Not a self-signed Certificate', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_WEAK_SIG_ALGO: {'text': 'Avoid known weak signature algorithms', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_WEAK_KEYS: {'text': 'Avoid known weak public key algorithms', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_DEPRECATED_TLS_PROTOCOLS: {'text': 'Avoid deprecated TLS protocols', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_DEPRECATED_DNSSEC_ALGO: {'text': 'Avoid deprecated DNSSEC algorithms', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_BASIC_CONSTRAINTS_CA: {'text': 'Leaf is not a CA', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_VALID_TLS_USAGE: {'text': 'Key usage appropriate for TLS', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_REVOCATION: {'text': 'Certificate chain not revoked', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_ROOT_CA_TRUST: {'text': 'Root CA Certificate is trusted', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_VALID_DNSSEC: {'text': 'DNSSEC Valid', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_VALID_CAA: {'text': 'CAA Valid', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_OCSP_STAPLE_SATISFIED: {'text': 'OCSP Staple satisfied', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    validator.VALIDATION_OCSP_MUST_STAPLE_SATISFIED: {'text': 'OCSP Must Staple satisfied', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    pci.VALIDATION_CA_TRUST: {'text': '[PCI] CA Trust', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    pci.VALIDATION_WEAK_KEY: {'text': '[PCI] Key Size', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    pci.VALIDATION_WEAK_CIPHER: {'text': '[PCI] Cipher bits', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    pci.VALIDATION_WEAK_PROTOCOL: {'text': '[PCI] Deprecated protocols', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    pci.VALIDATION_DEPRECATED_ALGO: {'text': '[PCI] Weak algorithms', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    pci.VALIDATION_KNOWN_VULN_COMPRESSION: {'text': '[PCI] Vulnerable compression', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    pci.VALIDATION_KNOWN_VULN_RENEGOTIATION: {'text': '[PCI] Vulnerable renegotiation', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    pci.VALIDATION_KNOWN_VULN_SESSION_RESUMPTION: {'text': '[PCI] Vulnerable session resumption', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    nist.VALIDATION_CA_TRUST: {'text': '[NIST] CA Trust', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    nist.VALIDATION_WEAK_KEY: {'text': '[NIST] Key Size', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    nist.VALIDATION_WEAK_CIPHER: {'text': '[NIST] Cipher bits', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    nist.VALIDATION_WEAK_PROTOCOL: {'text': '[NIST] Deprecated protocols', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    nist.VALIDATION_MTLS: {'text': '[NIST] Require ClientAuth', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    fips.VALIDATION_CA_TRUST: {'text': '[FIPS] CA Trust', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    fips.VALIDATION_WEAK_KEY: {'text': '[FIPS] Key Size', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    fips.VALIDATION_WEAK_CIPHER: {'text': '[FIPS] Cipher bits', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    fips.VALIDATION_WEAK_PROTOCOL: {'text': '[FIPS] Deprecated protocols', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    fips.VALIDATION_MTLS: {'text': '[FIPS] No ClientAuth for TLS1.0/1.1', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'certificate_version': {'text': 'Certificate Version'},
    'certificate_public_key_type': {'text': 'Public Key Type'},
    'certificate_public_key_curve': {'text': 'Public Key Curve', 'null_as': CLI_VALUE_NA, 'null_color': CLI_COLOR_NULL},
    'certificate_public_key_size': {'text': 'Public Key Size'},
    'certificate_public_key_exponent': {'text': 'Public Key Exponent', 'null_as': CLI_VALUE_NA, 'null_color': CLI_COLOR_NULL},
    'certificate_private_key_pem': {'text': 'Derived private key (PEM format)'},
    'certificate_signature_algorithm': {'text': 'Signature Algorithm'},
    'certificate_sha256_fingerprint': {'text': 'Fingerprint (sha256)'},
    'certificate_sha1_fingerprint': {'text': 'Fingerprint (sha1)'},
    'certificate_md5_fingerprint': {'text': 'Fingerprint (md5)'},
    'certificate_spki_fingerprint': {'text': 'Fingerprint (SPKI)'},
    'certificate_serial_number': {'text': 'Serial'},
    'certificate_serial_number_decimal': {'text': 'Serial (decimal)'},
    'certificate_serial_number_hex': {'text': 'Serial (hex)'},
    'certificate_subject': {'text': 'Certificate Subject'},
    'certificate_common_name': {'text': 'Certificate Subject CN'},
    'certificate_issuer': {'text': 'Issuer Subject CN'},
    'certificate_issuer_country': {'text': 'Issuer Country Code'},
    'certificate_not_before': {'text': 'Not Before'},
    'certificate_not_after': {'text': 'Not After'},
    'certificate_subject_key_identifier': {'text': 'Subject Key Identifier (SKI)'},
    'certificate_authority_key_identifier': {'text': 'Authority Key Identifier (AKI)'},
    'certificate_validation_type': {'text': 'Certificate Owner Validation Method'},
    'certificate_known_compromised': {'text': 'Compromised Certificate', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'certificate_key_compromised': {'text': 'Compromised Private Key', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'client_certificate_expected': {'text': 'Client Certificate Expected', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_ALERT, CLI_COLOR_NULL)},
    'certification_authority_authorization': {'text': 'CAA', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'revocation_ocsp_status': {'text': 'Revocation: OCSP'},
    'revocation_ocsp_response': {'text': 'Revocation: OCSP Response'},
    'revocation_ocsp_stapling': {'text': 'Revocation: OCSP Stapling', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'revocation_ocsp_must_staple': {'text': 'Revocation: OCSP Must Staple flag', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'revocation_ocsp_reason': {'text': 'Revocation: OCSP Revoked', 'null_as': CLI_VALUE_NOT_REVOKED, 'null_color': CLI_COLOR_OK, 'color': CLI_COLOR_NOK},
    'revocation_ocsp_time': {'text': 'Revocation: OCSP Revoked time', 'null_as': CLI_VALUE_NOT_REVOKED, 'null_color': CLI_COLOR_OK, 'color': CLI_COLOR_NOK},
    'revocation_crlite': {'text': 'Revocation: Mozilla CRLite', 'represent_as': (CLI_VALUE_REVOKED, CLI_VALUE_NOT_REVOKED), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'sni_support': {'text': 'Server Name Indicator (SNI)', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'negotiated_protocol': {'text': 'Negotiated Protocol'},
    'preferred_protocol': {'text': 'Server Preferred Protocol'},
    'offered_tls_versions': {'text': 'Offered TLS versions'},
    'negotiated_cipher': {'text': 'Negotiated Cipher'},
    'negotiated_cipher_bits': {'text': 'Negotiated Cipher bits'},
    'tls_version_intolerance': {'text': 'TLS version intolerance', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'tls_version_intolerance_versions': {'text': 'TLS version intolerance versions'},
    'tls_version_interference': {'text': 'TLS version interference', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'tls_version_interference_versions': {'text': 'TLS version interference versions'},
    'tls_long_handshake_intolerance': {'text': 'TLS long handshake intolerance', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'weak_cipher': {'text': 'Weak negotiated cipher', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'strong_cipher': {'text': 'Strong negotiated cipher', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_NOK), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'forward_anonymity': {'text': 'Forward Anonymity (FPS)', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'session_resumption_caching': {'text': 'Session Resumption (caching)', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'session_resumption_tickets': {'text': 'Session Resumption (tickets)', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'session_resumption_ticket_hint': {'text': 'Session Resumption (ticket hint)', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'client_renegotiation': {'text': 'Insecure Client Renegotiation', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'compression_support': {'text': 'TLS Compression', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'tlsa': {'text': 'TLSA/DANE', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'dnssec': {'text': 'DNSSEC', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'dnssec_algorithm': {'text': 'DNSSEC Algorithm', 'null_as': CLI_VALUE_NA, 'null_color': CLI_COLOR_NULL},
    'scsv': {'text': 'TLS downgrade prevention (SCSV)', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_INEFFECTIVE), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_expect_ct_report_uri': {'text': 'Expect-CT report-uri', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_hsts': {'text': 'HSTS', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_xfo': {'text': 'X-Frame-Options (XFO)', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_csp': {'text': 'Content Security Policy (CSP)', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_coep': {'text': 'Cross-Origin-Embedder-Policy (COEP)', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_coop': {'text': 'Cross-Origin-Opener-Policy (COOP)', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_corp': {'text': 'Cross-Origin-Resource-Policy (CORP)', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_nosniff': {'text': 'X-Content-Type-Options nosniff', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_unsafe_referrer': {'text': 'Referrer-Policy unsafe-url', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'http_xss_protection': {'text': 'X-XSS-Protection', 'represent_as': (CLI_VALUE_PRESENT, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_status_code': {'text': 'HTTP response status code'},
    'http1_support': {'text': 'HTTP/1', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'http1_1_support': {'text': 'HTTP/1.1', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_ALERT, CLI_COLOR_OK)},
    'http2_support': {'text': 'HTTP/2', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_ALERT, CLI_COLOR_OK)},
    'http2_cleartext_support': {'text': 'HTTP/2 Cleartext', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'possible_phish_or_malicious': {'text': 'Indicators of Phishing or Malware', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'trust_android': {'text': 'Android', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_android_status': {'text': ''},
    'trust_linux': {'text': 'Linux', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_linux_status': {'text': ''},
    'trust_java': {'text': 'Java', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_java_status': {'text': ''},
    'trust_certifi': {'text': 'Python', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_certifi_status': {'text': ''},
    'trust_ccadb': {'text': 'Common CA Database (CCADB)', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_ccadb_status': {'text': ''},
    'trust_russia': {'text': 'MinTsifry Rossii Database (Russia)', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_russia_status': {'text': ''},
}
RATING_ASCII = {
    'A+': """
 █████╗    ██╗
██╔══██╗   ██║
███████║████████╗
██╔══██║╚══██╔══╝
██║  ██║   ██║
╚═╝  ╚═╝   ╚═╝""",
    'A': """ █████╗
██╔══██╗
███████║
██╔══██║
██║  ██║
╚═╝  ╚═╝""",
    'B': """██████╗
██╔══██╗
██████╔╝
██╔══██╗
██████╔╝
╚═════╝""",
    'C': """ ██████╗
██╔════╝
██║
██║
╚██████╗
 ╚═════╝""",
    'D': """██████╗
██╔══██╗
██║  ██║
██║  ██║
██████╔╝
╚═════╝""",
    'E': """███████╗
██╔════╝
█████╗
██╔══╝
███████╗
╚══════╝""",
    'F': """███████╗
██╔════╝
█████╗
██╔══╝
██║
╚═╝""",
}
NEVER_SHOW = [
    'host',
    'port',
    "peer_address",
    "offered_ciphers",
    "certificate_san",
    "certificate_extensions",
    "certificate_is_self_signed",
    "certificate_private_key_pem",
    "subjectKeyIdentifier",
    "authorityKeyIdentifier",
    "certificate_expired",
    "certificate_validation_oid",
]
JSON_ONLY = [
    "certificate_expired",
    "certificate_extensions",
    "certificate_is_self_signed",
]
SERVER_JSON_ONLY = JSON_ONLY + [
    'host',
    'port',
    "peer_address",
    "offered_ciphers",
    "certificate_validation_oid",
]
SERVER_KEYS = [
    'certificate_validation_type',
    'certificate_is_self_signed',
    'certificate_subject',
    'certificate_issuer',
    'certificate_common_name',
    'certificate_intermediate_ca',
    'certificate_root_ca',
    'subjectKeyIdentifier',
    'authorityKeyIdentifier',
    'revocation_ocsp_status',
    'revocation_ocsp_response',
    'revocation_ocsp_reason',
    'revocation_ocsp_time',
    'revocation_ocsp_stapling',
    'revocation_ocsp_must_staple',
    'client_certificate_expected',
    'certification_authority_authorization',
    'tlsa',
    'dnssec',
    'dnssec_algorithm',
    'scsv',
    'compression_support',
    'tls_version_intolerance',
    'tls_version_intolerance_versions',
    'http_expect_ct_report_uri',
    'http_xss_protection',
    'http_status_code',
    'http1_support',
    'http1_1_support',
    'http2_support',
    'http2_cleartext_support',
    'sni_support',
    'negotiated_protocol',
    'preferred_protocol',
    'offered_tls_versions',
    'tls_version_interference',
    'tls_version_interference_versions',
    'tls_long_handshake_intolerance',
    'peer_address',
    'negotiated_cipher',
    'negotiated_cipher_bits',
    'weak_cipher',
    'strong_cipher',
    'forward_anonymity',
    'session_resumption_caching',
    'session_resumption_tickets',
    'session_resumption_ticket_hint',
    'client_renegotiation',
    'http_hsts',
    'http_xfo',
    'http_csp',
    'http_coep',
    'http_coop',
    'http_corp',
    'http_nosniff',
    'http_unsafe_referrer',
]
TRUST_KEYS = [
    'trust_ccadb',
    'trust_ccadb_status',
    'trust_java',
    'trust_java_status',
    'trust_android',
    'trust_android_status',
    'trust_linux',
    'trust_linux_status',
    'trust_certifi',
    'trust_certifi_status',
    'trust_russia',
    'trust_russia_status',
]
ROOT_SKIP = NEVER_SHOW + SERVER_KEYS + [
    'certificate_authority_key_identifier',
    'revocation_crlite',
    'common_name_defined',
    'possible_phish_or_malicious'
]
PEER_SKIP = NEVER_SHOW + SERVER_KEYS + TRUST_KEYS
SERVER_SKIP = NEVER_SHOW + TRUST_KEYS + [
    "certificate_root_ca",
    "certificate_intermediate_ca",
]
SUMMARY_SKIP = [
    'certificate_is_self_signed',
    'certificate_subject',
    'certificate_issuer',
    'certificate_common_name',
    'certificate_intermediate_ca',
    'certificate_root_ca',
    'certificate_signature_algorithm',
    'certificate_public_key_type',
    'certificate_public_key_curve',
    'certificate_public_key_size',
    'certificate_public_key_exponent',
    'certificate_version',
    'certificate_issuer',
    'certificate_issuer_country',
    'certificate_serial_number',
    'certificate_serial_number_decimal',
    'certificate_serial_number_hex',
    'certificate_not_before',
    'certificate_not_after',
    'subjectKeyIdentifier',
    'authorityKeyIdentifier',
    'revocation_ocsp_response',
    'revocation_ocsp_reason',
    'revocation_ocsp_time',
    'revocation_ocsp_stapling',
    'revocation_ocsp_must_staple',
    'client_certificate_expected',
    'scsv',
    'compression_support',
    'tls_version_intolerance',
    'tls_version_intolerance_versions',
    'http1_support',
    'http1_1_support',
    'http2_support',
    'http2_cleartext_support',
    'sni_support',
    'offered_tls_versions',
    'tls_version_interference',
    'tls_version_interference_versions',
    'tls_long_handshake_intolerance',
    'peer_address',
    'strong_cipher',
    'forward_anonymity',
    'session_resumption_caching',
    'session_resumption_tickets',
    'session_resumption_ticket_hint',
    'client_renegotiation',
    'http_expect_ct_report_uri',
    'http_xss_protection',
    'http_hsts',
    'http_xfo',
    'http_csp',
    'http_coep',
    'http_coop',
    'http_corp',
    'http_nosniff',
    'http_unsafe_referrer',
    'trust_ccadb_status',
    'trust_java_status',
    'trust_android_status',
    'trust_linux_status',
    'trust_certifi_status',
    'certificate_sha256_fingerprint',
    'certificate_sha1_fingerprint',
    'certificate_md5_fingerprint',
    'certificate_spki_fingerprint',
    'certificate_subject_key_identifier',
    'certificate_authority_key_identifier',
    'verification_details',
    'extensions'
]
FINGERPRINTS = [
    'certificate_sha256_fingerprint',
    'certificate_sha1_fingerprint',
    'certificate_md5_fingerprint',
    'certificate_spki_fingerprint',
    'certificate_subject_key_identifier',
    'certificate_authority_key_identifier'
]
