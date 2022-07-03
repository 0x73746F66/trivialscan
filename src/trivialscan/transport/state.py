import logging
from hashlib import sha1
from datetime import datetime
from urllib.parse import urlparse
from requests import Response
from ..certificate import BaseCertificate
from ..util import html_find_match

__module__ = "trivialscan.transport.state"

logger = logging.getLogger(__name__)


class HTTPState:
    _response: Response

    def __init__(self, response: Response) -> None:
        if not isinstance(response, Response):
            raise RuntimeError(
                "HTTPState.__init__ requires an instance of requests.Response"
            )
        self._response = response

    @property
    def hostname(self) -> str:
        parts = urlparse(self._response.request.url)
        return parts.hostname

    @property
    def port(self) -> int:
        parts = urlparse(self._response.request.url)
        default_port = 443 if parts.scheme == "https" else 80
        return parts.port or default_port

    @property
    def request_url(self) -> str:
        parts = urlparse(self._response.request.url)
        return parts.path

    @property
    def response_status(self) -> int:
        return self._response.status_code

    @property
    def response_headers(self) -> dict[str, str]:
        return {k: v for k, v in self._response.headers.items()}

    @property
    def response_title(self) -> str:
        return html_find_match(self.response_text, "title")

    @property
    def response_text(self) -> str:
        return self._response.text

    @property
    def response_body_hash(self) -> str:
        return sha1(self.response_text.encode()).hexdigest()

    @property
    def response_json(self) -> dict | list:
        return self._response.json()

    def to_dict(self, include_transport: bool = False):
        data = {
            "title": self.response_title,
            "status_code": self.response_status,
            "headers": self.response_headers,
            "body_hash": self.response_body_hash,
        }
        if include_transport:
            data["_transport"] = {
                "hostname": self.hostname,
                "port": self.port,
                "peer_address": self.peer_address,
            }

        return data

    def header_exists(self, name: str, includes_value: str) -> bool:
        return (
            name in self._response.headers
            and includes_value in self._response.headers[name]
        )


class TLSState:
    hostname: str = None
    port: int = 443
    sni_support: bool = None
    peer_address: str = None
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
    offered_ciphers: list = []
    forward_anonymity: bool = None
    negotiated_cipher: str = None
    negotiated_cipher_bits: int = None

    def from_transport(self, transport):
        self.hostname = getattr(transport, "hostname", self.hostname)
        self.port = getattr(transport, "port", self.port)
        self.sni_support = getattr(transport, "sni_support", self.sni_support)
        self.peer_address = getattr(transport, "peer_address", self.peer_address)
        return self

    def from_http_state(self, state: HTTPState):
        self.hostname = getattr(state, "hostname", self.hostname)
        self.port = getattr(state, "port", self.port)
        self.sni_support = getattr(state, "sni_support", self.sni_support)
        self.peer_address = getattr(state, "peer_address", self.peer_address)
        return self

    def to_dict(self, include_transport: bool = False) -> dict:
        data = {
            "certificates": [cert.to_dict() for cert in self.certificates],
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
                "versions": sorted(list(set(self.tls_version_intolerance_versions))),
            },
            "version_interference": {
                "result": self.tls_version_interference,
                "versions": sorted(list(set(self.tls_version_interference_versions))),
            },
            "session_resumption": {
                "caching": self.session_resumption_caching,
                "tickets": self.session_resumption_tickets,
                "ticket_hint": self.session_resumption_ticket_hint,
            },
            "certificate_mtls_expected": self.certificate_mtls_expected,
            "sni_support": self.sni_support,
        }
        if include_transport:
            data["_transport"] = {
                "hostname": self.hostname,
                "port": self.port,
                "peer_address": self.peer_address,
            }

        return data


class TransportStore:
    tls_state: TLSState = TLSState()
    http_states: list[HTTPState] = []
    evaluations: list = []

    def to_dict(self) -> dict:
        data = {
            "last_updated": datetime.utcnow().replace(microsecond=0).isoformat(),
            "transport": {
                "hostname": self.tls_state.hostname,
                "port": self.tls_state.port,
                "sni_support": self.tls_state.sni_support,
                "peer_address": self.tls_state.peer_address,
                "certificate_mtls_expected": self.tls_state.certificate_mtls_expected,
            },
            "tls": self.tls_state.to_dict(),
            "http": [http.to_dict() for http in self.http_states],
            "evaluations": self.evaluations,
        }
        return data
