import logging
from hashlib import sha1
from datetime import datetime
from dataclasses import asdict
from urllib.parse import urlparse
from typing import Union

from requests import Response
from OpenSSL.crypto import (
    load_certificate,
    FILETYPE_PEM,
)

from ..certificate import (
    BaseCertificate,
    ClientCertificate,
    IntermediateCertificate,
    LeafCertificate,
    RootCertificate,
)
from ..util import html_find_match
from ..constants import OPENSSL_MAP_TO_RFC

__module__ = "trivialscan.transport.state"

logger = logging.getLogger(__name__)


class HTTPState:
    def __init__(self, response: Response) -> None:
        if not isinstance(response, Response):
            raise RuntimeError(
                "HTTPState.__init__ requires an instance of requests.Response"
            )
        self._response: Response = response

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
        return html_find_match(self.response_text, find="title")

    @property
    def response_text(self) -> str:
        return self._response.text

    @property
    def response_body_hash(self) -> str:
        return sha1(self.response_text.encode()).hexdigest()

    @property
    def response_json(self) -> Union[dict, list]:
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
            }

        return data

    def header_exists(self, name: str, includes_value: str = None) -> bool:
        if includes_value is None:
            return name in self._response.headers
        return (
            name in self._response.headers
            and includes_value in self._response.headers[name]
        )


class TLSState:
    def __init__(self) -> None:
        self.hostname: str = None
        self.port: int = 443
        self.sni_support: bool = None
        self.peer_address: str = None
        self.certificate_mtls_expected: bool = None
        self.client_certificate_trusted: bool = None
        self.client_certificate_match: bool = None
        self.expected_client_subjects: list[str] = []
        self.certificates: list[BaseCertificate] = []
        self.negotiated_protocol: str = None
        self.preferred_protocol: str = None
        self.offered_tls_versions: list = []
        self.session_resumption_cache_mode: str = None
        self.session_resumption_tickets: bool = None
        self.session_resumption_ticket_hint: bool = None
        self.offered_ciphers: list = []
        self.forward_anonymity: bool = None
        self.negotiated_cipher: str = None
        self.negotiated_cipher_bits: int = None

    def from_dict(self, data: dict) -> None:
        for certificate in data.get("certificates", []):
            if certificate["type"] == "root":
                self.certificates.append(
                    RootCertificate(
                        load_certificate(FILETYPE_PEM, certificate["pem"].encode())
                    )
                )
            if certificate["type"] == "leaf":
                self.certificates.append(
                    LeafCertificate(
                        load_certificate(FILETYPE_PEM, certificate["pem"].encode())
                    )
                )
            if certificate["type"] == "intermediate":
                self.certificates.append(
                    IntermediateCertificate(
                        load_certificate(FILETYPE_PEM, certificate["pem"].encode())
                    )
                )
            if certificate["type"] == "client":
                self.certificates.append(
                    ClientCertificate(
                        load_certificate(FILETYPE_PEM, certificate["pem"].encode())
                    )
                )
        self.hostname = data.get("transport", {}).get("hostname")
        self.port = data.get("transport", {}).get("port", 443)
        self.peer_address = data.get("transport", {}).get("peer_address")
        self.sni_support = data["tls"].get("client", {}).get("sni_support")
        self.certificate_mtls_expected = (
            data["tls"].get("client", {}).get("certificate_mtls_expected")
        )
        self.client_certificate_trusted = (
            data["tls"].get("client", {}).get("certificate_trusted")
        )
        self.client_certificate_match = (
            data["tls"].get("client", {}).get("certificate_match")
        )
        self.expected_client_subjects = (
            data["tls"].get("client", {}).get("expected_client_subjects", [])
        )
        self.negotiated_protocol = data["tls"].get("protocol", {}).get("negotiated")
        self.preferred_protocol = data["tls"].get("protocol", {}).get("preferred")
        self.offered_tls_versions = data["tls"].get("protocol", {}).get("offered", [])
        self.session_resumption_cache_mode = (
            data["tls"].get("session_resumption", {}).get("cache_mode")
        )
        self.session_resumption_tickets = (
            data["tls"].get("session_resumption", {}).get("tickets")
        )
        self.session_resumption_ticket_hint = (
            data["tls"].get("session_resumption", {}).get("ticket_hint")
        )
        self.offered_ciphers = data["tls"].get("cipher", {}).get("offered", [])
        self.forward_anonymity = data["tls"].get("cipher", {}).get("forward_anonymity")
        self.negotiated_cipher = data["tls"].get("cipher", {}).get("negotiated")
        self.negotiated_cipher_bits = (
            data["tls"].get("cipher", {}).get("negotiated_bits")
        )

    def to_dict(self, include_transport: bool = False) -> dict:
        data = {
            "certificates": [cert.to_dict() for cert in self.certificates],
            "client": {
                "sni_support": self.sni_support,
                "certificate_mtls_expected": self.certificate_mtls_expected,
                "certificate_trusted": self.client_certificate_trusted,
                "certificate_match": self.client_certificate_match,
                "expected_client_subjects": sorted(
                    list(set(self.expected_client_subjects))
                ),
            },
            "cipher": {
                "forward_anonymity": self.forward_anonymity,
                "offered": sorted(list(set(self.offered_ciphers))),
                "offered_rfc": sorted(
                    list(
                        set(
                            OPENSSL_MAP_TO_RFC.get(cipher, cipher)
                            for cipher in self.offered_ciphers
                        )
                    )
                ),
                "negotiated": self.negotiated_cipher,
                "negotiated_bits": self.negotiated_cipher_bits,
                "negotiated_rfc": OPENSSL_MAP_TO_RFC.get(
                    self.negotiated_cipher_bits, self.negotiated_cipher_bits
                ),
            },
            "protocol": {
                "negotiated": self.negotiated_protocol,
                "preferred": self.preferred_protocol,
                "offered": sorted(list(set(self.offered_tls_versions))),
            },
            "session_resumption": {
                "cache_mode": self.session_resumption_cache_mode,
                "tickets": self.session_resumption_tickets,
                "ticket_hint": self.session_resumption_ticket_hint,
            },
        }
        if include_transport:
            data["_transport"] = {
                "hostname": self.hostname,
                "port": self.port,
                "peer_address": self.peer_address,
            }

        return data


class TransportStore:
    def __init__(self, **kwargs) -> None:
        self.tls_state: TLSState = TLSState()
        self.http_states: list[HTTPState] = []
        self.evaluations: list["EvaluationResult"] = []
        self.error: tuple[str, str] = None
        if kwargs.get("evaluations"):
            self.evaluations = kwargs["evaluations"]
        if kwargs.get("tls"):
            self.tls_state.from_dict(kwargs.get("tls"))

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
            "score": 0,
            "results": {
                "pass": 0,
                "info": 0,
                "warn": 0,
                "fail": 0,
            },
        }
        if self.error:
            data["error"] = self.error
            return data

        data["evaluations"] = [asdict(e) for e in self.evaluations]
        for evaluation in data["evaluations"]:
            for res in ["pass", "info", "warn", "fail"]:
                if evaluation["result_level"] == res:
                    data["results"][res] += 1
            if "score" in evaluation:
                data["score"] += evaluation["score"]

        data["tls"] = self.tls_state.to_dict()
        certificates = set()
        for certdata in data["tls"]["certificates"]:
            certificates.add(certdata["sha1_fingerprint"])

        data["certificates"] = sorted(list(certificates))
        data["http"] = [http.to_dict() for http in self.http_states]

        return data
