import logging
import ssl
from OpenSSL import SSL
from OpenSSL.crypto import X509
from .. import util, constants
from ..exceptions import TransportError
from ..transport import TLSTransport

__module__ = "trivialscan.transport.insecure"
logger = logging.getLogger(__name__)


class InsecureTransport(TLSTransport):
    def __init__(self, hostname: str, port: int = 443) -> None:
        super().__init__(hostname, port)

    def connect_insecure(self, cafiles: list = None, use_sni: bool = False) -> None:
        if cafiles is not None:
            if not isinstance(cafiles, list):
                raise TypeError(
                    f"provided an invalid type {type(cafiles)} for cafiles, expected list"
                )
            valid_cafiles = util.filter_valid_files_urls(cafiles)
            if valid_cafiles is False:
                raise AttributeError(
                    "cafiles was provided but is not a valid URLs or files do not exist"
                )
            if isinstance(valid_cafiles, list):
                self._cafiles = valid_cafiles

        tls_version_map = {
            SSL.SSL3_VERSION: constants.OPENSSL_VERSION_LOOKUP[SSL.SSL3_VERSION],
            SSL.TLS1_VERSION: constants.OPENSSL_VERSION_LOOKUP[SSL.TLS1_VERSION],
            SSL.TLS1_1_VERSION: constants.OPENSSL_VERSION_LOOKUP[SSL.TLS1_1_VERSION],
            SSL.TLS1_2_VERSION: constants.OPENSSL_VERSION_LOOKUP[SSL.TLS1_2_VERSION],
            SSL.TLS1_3_VERSION: constants.OPENSSL_VERSION_LOOKUP[SSL.TLS1_3_VERSION],
        }
        self.store.tls_state.sni_support = all([use_sni, ssl.HAS_SNI])
        for version, label in tls_version_map.items():
            self.connect(
                tls_version=version, use_sni=use_sni
            )  # Skip HTTP testing until negotiated
            if not isinstance(self.server_certificate, X509):
                logger.warning(
                    f"{self.store.tls_state.hostname}:{self.store.tls_state.port} Failed {constants.OPENSSL_VERSION_LOOKUP[version]} use_sni {use_sni}"
                )
                continue

            if version == SSL.TLS1_3_VERSION:
                # server can only prefer this too, that's how TLS1.3 was intended
                self.store.tls_state.preferred_protocol = (
                    f"{label} ({hex(constants.PROTOCOL_VERSION[label])})"
                )

            if self.store.tls_state.negotiated_protocol:
                break

        if not self.store.tls_state.negotiated_protocol:
            raise TransportError(
                f"server listening at {self.store.tls_state.hostname}:{self.store.tls_state.port} did not respond to any known TLS protocols"
            )

        negotiated = self.specify_tls_version(use_sni=use_sni)
        if negotiated:
            negotiated_label = (
                f"{negotiated} ({hex(constants.PROTOCOL_VERSION[negotiated])})"
            )
            self.store.tls_state.preferred_protocol = negotiated_label
            self.store.tls_state.offered_tls_versions.append(negotiated_label)
        else:
            self.store.tls_state.preferred_protocol = (
                self.store.tls_state.negotiated_protocol
            )
        for version, label in tls_version_map.items():
            label = f"{label} ({hex(constants.PROTOCOL_VERSION[label])})"
            if label in self.store.tls_state.offered_tls_versions:
                continue
            negotiated = self.specify_tls_version(
                max_tls_version=version, use_sni=use_sni
            )
            if negotiated:
                self.store.tls_state.offered_tls_versions.append(label)
