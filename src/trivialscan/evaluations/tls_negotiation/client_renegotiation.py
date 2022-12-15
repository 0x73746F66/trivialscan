from OpenSSL import SSL, _util
from ... import util
from ...transport import TLSTransport
from .. import BaseEvaluationTask

TIMEOUT = 3


class EvaluationTask(BaseEvaluationTask):
    probe_info: str = "TLS and attempt client renegotiation"
    client_renegotiation: bool = False

    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        tspt = TLSTransport(
            hostname=self.transport.store.tls_state.hostname,
            port=self.transport.store.tls_state.port,
        )
        ctx = tspt.prepare_context()
        ctx.set_options(
            _util.lib.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
            | _util.lib.SSL_OP_LEGACY_SERVER_CONNECT
            | _util.lib.SSL_OP_TLS_ROLLBACK_BUG
        )
        conn = tspt.prepare_connection(
            context=ctx, sock=tspt.prepare_socket(timeout=TIMEOUT)
        )
        try:
            conn.settimeout(TIMEOUT)
            util.do_handshake(conn)
            self.renegotiate(conn)
            conn.shutdown()
        except SSL.Error:
            pass
        finally:
            conn.close()
        return self.client_renegotiation

    def renegotiate(self, conn: SSL.Connection):
        total_renegotiations = conn.total_renegotiations()
        try:
            if conn.renegotiate():
                conn.setblocking(0)
                util.do_handshake(conn)
        except SSL.Error:
            pass
        self.client_renegotiation = conn.total_renegotiations() > total_renegotiations
