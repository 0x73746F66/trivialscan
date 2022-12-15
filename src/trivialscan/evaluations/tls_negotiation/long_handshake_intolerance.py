import logging
import ssl
import socket
import idna
from socket import AF_INET, SOCK_STREAM
from certifi import where
from OpenSSL import SSL
from ...constants import ALL_CIPHERS
from ...util import do_handshake
from ...transport import TLSTransport
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    probe_info = "Sending 3458 bytes Client Hello"
    default_connect_method = "SSLv23_METHOD"

    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        self.long_handshake_intolerance_versions = set()
        super().__init__(transport, metadata, config)

    def evaluate(self):
        """
        If the Client Hello messages longer than 255 bytes and the connection fails
        Using ALL_CIPHERS is 3458 bytes so our Client Hello will be sufficiently long
        """
        tls_versions = [
            SSL.SSL3_VERSION,
            SSL.TLS1_VERSION,
            SSL.TLS1_1_VERSION,
            SSL.TLS1_2_VERSION,
            SSL.TLS1_3_VERSION,
        ]
        for version in tls_versions:
            try:
                if self.long_handshake_intolerance(version):
                    self.long_handshake_intolerance_versions.add(version)
            except AttributeError as err:
                logger.debug(err, exc_info=True)

        self.substitution_metadata["long_handshake_intolerance_versions"] = list(
            self.long_handshake_intolerance_versions
        )
        return len(self.long_handshake_intolerance_versions) > 0

    def long_handshake_intolerance(self, version) -> bool:
        native_ssl_openssl_version_map = {
            768: ssl.PROTOCOL_SSLv3,
            769: ssl.PROTOCOL_TLSv1,
            770: ssl.PROTOCOL_TLSv1_1,
            771: ssl.PROTOCOL_TLSv1_2,
            772: ssl.PROTOCOL_TLSv1_2,
        }
        protocol = native_ssl_openssl_version_map[version]
        ctx = ssl.SSLContext(protocol)
        sock = socket.socket(AF_INET, SOCK_STREAM)
        context = SSL.Context(method=getattr(SSL, self.default_connect_method))
        if version == SSL.TLS1_3_VERSION:
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_1
            ctx.options |= ssl.OP_NO_TLSv1_2
            ctx.options |= ssl.OP_NO_COMPRESSION
            context.set_options(
                SSL.OP_NO_SSLv2
                | SSL.OP_NO_SSLv3
                | SSL.OP_NO_TLSv1
                | SSL.OP_NO_TLSv1_1
                | SSL.OP_NO_TLSv1_2
                | SSL.OP_NO_COMPRESSION
            )
        if version == SSL.TLS1_2_VERSION:
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_1
            ctx.options |= ssl.OP_NO_TLSv1_3
            ctx.options |= ssl.OP_NO_COMPRESSION
            context.set_options(
                SSL.OP_NO_SSLv2
                | SSL.OP_NO_SSLv3
                | SSL.OP_NO_TLSv1
                | SSL.OP_NO_TLSv1_1
                | SSL.OP_NO_TLSv1_3
                | SSL.OP_NO_COMPRESSION
            )
        if version == SSL.TLS1_1_VERSION:
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_2
            ctx.options |= ssl.OP_NO_TLSv1_3
            ctx.options |= ssl.OP_NO_COMPRESSION
            context.set_options(
                SSL.OP_NO_SSLv2
                | SSL.OP_NO_SSLv3
                | SSL.OP_NO_TLSv1
                | SSL.OP_NO_TLSv1_2
                | SSL.OP_NO_TLSv1_3
                | SSL.OP_NO_COMPRESSION
            )
        if version == SSL.TLS1_VERSION:
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3
            ctx.options |= ssl.OP_NO_TLSv1_1
            ctx.options |= ssl.OP_NO_TLSv1_2
            ctx.options |= ssl.OP_NO_TLSv1_3
            ctx.options |= ssl.OP_NO_COMPRESSION
            context.set_options(
                SSL.OP_NO_SSLv2
                | SSL.OP_NO_SSLv3
                | SSL.OP_NO_TLSv1_1
                | SSL.OP_NO_TLSv1_2
                | SSL.OP_NO_TLSv1_3
                | SSL.OP_NO_COMPRESSION
            )

        sock.settimeout(1)
        ctx.verify_mode = ssl.CERT_REQUIRED
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=where())
        ctx.set_ciphers(ALL_CIPHERS)
        context.set_cipher_list(ALL_CIPHERS.encode())
        context.set_min_proto_version(version)
        context.set_max_proto_version(version)
        conn = SSL.Connection(
            context,
            ctx.wrap_socket(
                sock,
                do_handshake_on_connect=False,
                server_hostname=self.transport.store.tls_state.hostname,
            ),
        )
        negotiated_cipher = None
        try:
            conn.connect(
                (
                    self.transport.store.tls_state.hostname,
                    self.transport.store.tls_state.port,
                )
            )
            conn.set_connect_state()
            if ssl.HAS_SNI:
                conn.set_tlsext_host_name(
                    idna.encode(self.transport.store.tls_state.hostname)
                )
            conn.setblocking(1)
            do_handshake(conn)
            negotiated_cipher = conn.get_cipher_name()
            conn.shutdown()
        except Exception as ex:
            logger.debug(ex, exc_info=True)
        finally:
            conn.close()
        return negotiated_cipher is None
