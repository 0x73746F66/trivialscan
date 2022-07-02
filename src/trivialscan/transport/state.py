from datetime import datetime
from tlstrust.context import SOURCE_CCADB
from ..certificate import BaseCertificate

__module__ = "trivialscan.transport.state"


class TransportState:
    certificate_mtls_expected: bool = None
    certificates: list[BaseCertificate] = []
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
    http_response_hash: str = None
    http_response_text: str = None
    http_response_title: str = None
    http_headers: dict[str, str] = {}
    evaluations: list = []

    def to_dict(self) -> dict:
        data = {
            "last_updated": datetime.utcnow().replace(microsecond=0).isoformat(),
            "transport": {
                "hostname": self.hostname,
                "port": self.port,
                "sni_support": self.sni_support,
                "peer_address": self.peer_address,
                "certificate_mtls_expected": self.certificate_mtls_expected,
            },
            "tls": {
                "cipher": {
                    "forward_anonymity": self.forward_anonymity,
                    "offered": sorted(list(set(self.offered_ciphers))),
                    "negotiated": self.negotiated_cipher,
                    "negotiated_bits": self.negotiated_cipher_bits,
                },
                "protocol": {
                    "negotiated": self.negotiated_protocol,
                    "preferred": self.preferred_protocol,
                    "offered": sorted(list(set(self.offered_tls_versions))),
                },
                "version_intolerance": {
                    "result": self.tls_version_intolerance,
                    "versions": sorted(
                        list(set(self.tls_version_intolerance_versions))
                    ),
                },
                "version_interference": {
                    "result": self.tls_version_interference,
                    "versions": sorted(
                        list(set(self.tls_version_interference_versions))
                    ),
                },
                "session_resumption": {
                    "caching": self.session_resumption_caching,
                    "tickets": self.session_resumption_tickets,
                    "ticket_hint": self.session_resumption_ticket_hint,
                },
            },
            "http": {
                "title": self.http_response_title,
                "status_code": self.http_status_code,
                "headers": self.http_headers,
                "body_hash": self.http_response_hash,
            },
            "certificates": [cert.to_dict() for cert in self.certificates],
            "evaluations": self.evaluations,
        }
        return data
