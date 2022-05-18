from datetime import datetime
from tlstrust.context import SOURCE_CCADB
from ..certificate import BaseCertificate

__module__ = "trivialscan.transport.state"


class TransportState:
    certificate_mtls_expected: bool = None
    certificates: list[BaseCertificate]
    negotiated_protocol: str = None
    preferred_protocol: str = None
    offered_tls_versions: list = []
    tls_version_intolerance: bool = None
    tls_version_intolerance_versions: list = []
    tls_version_interference: bool = None
    tls_version_interference_versions: list = []
    session_resumption_caching: bool = None
    session_resumption_tickets: bool = None
    session_resumption_ticket_hint: bool = None
    hostname: str = None
    port: int = 443
    sni_support: bool = None
    peer_address: str = None
    offered_ciphers: list = []
    forward_anonymity: bool = None
    negotiated_cipher: str = None
    negotiated_cipher_bits: int = None
    http_status_code: int = None
    http1_support: bool = None
    http1_1_support: bool = None
    http2_support: bool = None
    http2_cleartext_support: bool = None
    http_headers: dict[str, str] = {}
    evaluations: list = []
    """config exists

    client_renegotiation
    compression_support
    dnssec
    deprecated_dnssec_algorithm
    deprecated_protocol_negotiated
    known_weak_cipher_negotiated
    known_weak_cipher_offered
    rc4_cipher_offered
    cbc_cipher_offered
    strong_cipher_negotiated
    strong_cipher_offered
    known_weak_signature_algorithm
    fallback_scsv
    tls_robot
    private_key_known_compromised
    revocation_crlite
    secure_renegotiation

    TODO
    tlsa                            https://www.cloudns.net/wiki/article/342/
    possible_phish_or_malicious
    tls_long_handshake_intolerance
    http2_cleartext_support
    http_expect_ct_report_uri
    http_hsts
    http_xfo
    http_csp
    http_coep
    http_coop
    http_corp
    http_nosniff
    http_unsafe_referrer
    http_xss_protection
    avoid_known_weak_keys
    basic_constraints_ca
    certificate_valid_tls_usage
    common_name_defined
    common_name_valid
    match_hostname
    not_expired
    issued_past_tense
    not_revoked
    not_self_signed
    trusted_ca
    TLS extension intolerance:
    Incorrect SNI alerts:
    Uses common DH primes:
    DH public server param (Ys) reuse:
    ECDH public server param reuse:
    POODLE; CBC Padding Oracle Vulnerability; SSLv3 or CBC (GOLDENDOODLE, Zombie POODLE, Sleeping POODLE, POODLE BITES, POODLE 2.0, CVE-2015-4458, CVE-2016-2107, and Invalid Mac 0-length record CVE-2019-1559)
    HEARTBLEED: CVE-2014-0160 OpenSSL Vulnerability allowing attackers to access random server memory that could potentially disclose any sensitive data the server is storing
    CCS Injection: CVE-2014-0224 TLS feature providing MitM attackers opertunity to leverage Change-Cipher-Specs allowing the use of attacker preferred ciphers that are available and potentially offer an exploit path
    FREAK: weak export cipher suites, RSA of moduli of less than 512 bits, trivial to factor https://tools.keycdn.com/freak
    Logjam: similar to the FREAK attack but except that Logjam attacks the 512-bit DH export key exchange instead of the RSA key exchange. disable support for all DHE_EXPORT cipher suites
    LUCKY13:
    SWEET32:
    DROWN:
    RC4:
    CBC:
    HEARTBLEED: Heartbeat extension RFC6520 is leveraged for HEARTBLEED vulnerability
    Ticketbleed:
    EMS: Extended Master Secret extension provides additional security to SSL sessions and prevents certain MitM attacks
    EC_POINT_FORMAT TLS extension, RFC 8422 5.1.2: uncompressed point format is obsolete so it is perfectly fine for a client to not include this extension, if included it must have exactly the value 0 (Uncompressed) Point Format for NIST Curves
    PCI:
        No known vulnerabilities
        All the certificates provided by the server are trusted
        No known weak ciphers, protocols, keys, signatures, elliptic curves
    HIPAA:
        All the X509 certificates provided by the server are in version 3
        supports OCSP stapling
        No known weak ciphers, protocols, keys, signatures, elliptic curves
        Support Extended Master Secret (EMS) extension for TLS versions ≤1.2
        Supports the Uncompressed Point Format for NIST Curves, or; no EC_POINT_FORMAT TLS extension
    """

    def to_dict(self) -> dict:
        data = {
            "_metadata": {
                "last_updated": datetime.utcnow().replace(microsecond=0).isoformat(),
                "transport": {
                    "hostname": self.hostname,
                    "port": self.port,
                    "sni_support": self.sni_support,
                    "peer_address": self.peer_address,
                    "certificate_mtls_expected": self.certificate_mtls_expected,
                },
                "certificates": [cert.to_dict() for cert in self.certificates],
                "tls": {
                    "cipher": {
                        "forward_anonymity": self.forward_anonymity,
                        "offered": list(set(self.offered_ciphers)),
                        "negotiated": self.negotiated_cipher,
                        "negotiated_bits": self.negotiated_cipher_bits,
                    },
                    "protocol": {
                        "negotiated": self.negotiated_protocol,
                        "preferred": self.preferred_protocol,
                        "offered": list(set(self.offered_tls_versions)),
                    },
                    "version_intolerance": {
                        "result": self.tls_version_intolerance,
                        "versions": list(set(self.tls_version_intolerance_versions)),
                    },
                    "version_interference": {
                        "result": self.tls_version_interference,
                        "versions": list(set(self.tls_version_interference_versions)),
                    },
                    "session_resumption": {
                        "caching": self.session_resumption_caching,
                        "tickets": self.session_resumption_tickets,
                        "ticket_hint": self.session_resumption_ticket_hint,
                    },
                },
                "http": {
                    "status_code": self.http_status_code,
                    "v1_support": self.http1_support,
                    "v1_1_support": self.http1_1_support,
                    "v2_support": self.http2_support,
                    "h2c_support": self.http2_cleartext_support,
                    "headers": self.http_headers,
                },
            },
        }
        return data

    def common_validation(self, trust_context: int = SOURCE_CCADB) -> bool:
        # Most browsers (and software generally) check only:
        # - common name exists
        # - common name well formed
        # - hostname match common name or SAN
        # - leaf not expired
        # - root CA exists in trust stores
        return True

    def is_valid(self, trust_context: int = SOURCE_CCADB) -> bool:
        # Proper RFC defined MUST validations:
        # - common_validation
        # - intermediates common_validation
        # - root common_validation
        # - no revocations
        return True

    def best_practive_valid(self, trust_context: int = SOURCE_CCADB) -> bool:
        # RFC defined SHOULD validations:
        # - is_valid
        # - no deprecated protocols, signatures, or ciphers
        # - all certificates issued in past tense
        # - server not sending useless certificates
        # - CAA
        # - Not DV
        # - TLS1.3
        # - Only PFS
        # - HSTS
        # - SCSV
        # - Secure Renegotiation
        # - No known vulnerabilities
        return True

    def pci_validation(self, trust_context: int = SOURCE_CCADB) -> bool:
        # PCI DSS v4.0
        return True

    def fips_valid(self, trust_context: int = SOURCE_CCADB) -> bool:
        # FIPS 140-2 (NIST SP800-131A transition mode)
        return self.nist_validation(transition_mode=True)

    def hipaa_valid(self, trust_context: int = SOURCE_CCADB) -> bool:
        # HIPAA/HITECH requires NIST SP800
        return self.nist_validation(transition_mode=True)

    def nist_validation(
        self, transition_mode: bool = False, trust_context: int = SOURCE_CCADB
    ) -> bool:
        # NIST SP800-131A strict mode (superset of NIST SP800-52 R2)
        return True
