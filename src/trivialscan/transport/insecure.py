import logging
import ssl
from OpenSSL import SSL
from OpenSSL.crypto import X509
import idna
from .. import util, constants
from ..exceptions import TransportError
from ..transport import Transport

__module__ = "trivialscan.transport.insecure"
logger = logging.getLogger(__name__)


class InsecureTransport(Transport):
    def __init__(self, hostname: str, port: int = 443) -> None:
        super().__init__(hostname, port)

    def do_http(self, tls_version: int):
        proto_map = {
            "HTTP/1.0": "http1_",
            "HTTP/1.1": "http1_1_",
        }
        for protocol, prefix in proto_map.items():
            logger.debug(
                f"[{self._state.hostname}:{self._state.port}] protocol {protocol}"
            )
            ctx = self.prepare_context()
            ctx.set_max_proto_version(tls_version)
            conn = SSL.Connection(context=ctx, socket=self.prepare_socket())
            if ssl.HAS_SNI:
                conn.set_tlsext_host_name(idna.encode(self._state.hostname))
            try:
                conn.connect((self._state.hostname, self._state.port))
                conn.set_connect_state()
                conn.setblocking(1)
                util.do_handshake(conn)
                try:
                    head, _ = self.do_request(conn, protocol=protocol)
                except SSL.ZeroReturnError:
                    conn.close()
                    continue
                logger.info(
                    f"[{self._state.hostname}:{self._state.port}] Response headers:\n{head}"
                )
                self._state.http_headers = Transport.parse_header(head)
                http_status_code = int(self._state.http_headers["response_code"])
                http_statuses = [505]
                http_support = self._state.http_headers["protocol"].startswith(protocol)
                if isinstance(self._state.http_status_code, int):
                    http_statuses.append(self._state.http_status_code)
                if http_support:
                    http_statuses.append(http_status_code)
                if self._state.certificate_mtls_expected and not str(
                    http_status_code
                ).startswith("2"):
                    http_statuses.append(511)
                self._state.http_status_code = min(http_statuses)
                setattr(self._state, f"{prefix}support", http_support)
                if self.client_initiated_renegotiation is None:
                    total_renegotiations = conn.total_renegotiations()
                    try:
                        proceed = conn.renegotiate()
                        if proceed:
                            conn.setblocking(0)
                            util.do_handshake(conn)
                            self.client_initiated_renegotiation = (
                                conn.total_renegotiations() > total_renegotiations
                            )
                    except SSL.ZeroReturnError:
                        pass
                    except Exception as ex:
                        logger.warning(ex, exc_info=True)
                    self.client_initiated_renegotiation = (
                        self.client_initiated_renegotiation is True
                    )
            finally:
                conn.close()

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

        tls_versions = [
            SSL.SSL3_VERSION,
            SSL.TLS1_VERSION,
            SSL.TLS1_1_VERSION,
            SSL.TLS1_2_VERSION,
            SSL.TLS1_3_VERSION,
        ]
        for version in tls_versions:
            self.connect(
                tls_version=version, use_sni=use_sni
            )  # Skip HTTP testing until negotiated
            if not isinstance(self.server_certificate, X509):
                logger.info(
                    f"[{self._state.hostname}:{self._state.port}] Failed {constants.OPENSSL_VERSION_LOOKUP[version]} use_sni {use_sni}"
                )
                continue

            if all([use_sni, ssl.HAS_SNI]):
                self._state.sni_support = True

            if version == SSL.TLS1_3_VERSION:
                # Already the highest TLS protocol, no downgrade possible
                self.tls_downgrade = False
                # server can only prefer this too
                self._state.preferred_protocol = constants.OPENSSL_VERSION_LOOKUP[
                    version
                ]

            self.do_http(version)
            return

        raise TransportError(
            f"server listening at [{self._state.hostname}:{self._state.port}] did not respond to any known TLS protocols"
        )
