import ssl
from OpenSSL import SSL, _util
import idna
from ...transport import Transport
from ...constants import OPENSSL_VERSION_LOOKUP, PROTOCOL_TEXT_MAP, TLS1_3_LABEL
from .. import BaseEvaluationTask

SSL_MODE_SEND_FALLBACK_SCSV = 0x00000080


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: Transport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)
        self._supports_fallback_scsv = None
        self._state = transport.get_state()

    def evaluate(self) -> bool | None:
        # no downgrade possible using TLS 1.3
        if all(
            [
                self._state.preferred_protocol
                == OPENSSL_VERSION_LOOKUP[SSL.TLS1_3_VERSION],
                self._state.negotiated_protocol
                == OPENSSL_VERSION_LOOKUP[SSL.TLS1_3_VERSION],
            ]
        ):
            self._supports_fallback_scsv = True
        # short circuit if obvious downgrade occurred
        if self._state.preferred_protocol not in [
            TLS1_3_LABEL,
            self._state.negotiated_protocol,
        ]:
            self._supports_fallback_scsv = False
        # should only occur if using only SSL3
        if self._state.preferred_protocol not in PROTOCOL_TEXT_MAP.keys():
            return None
        if isinstance(self._supports_fallback_scsv, bool):
            return self._supports_fallback_scsv

        self._supports_fallback_scsv = False
        ctx = self._transport.prepare_context()
        ctx.set_max_proto_version(PROTOCOL_TEXT_MAP[self._state.preferred_protocol])
        ctx.set_mode(SSL_MODE_SEND_FALLBACK_SCSV)
        ctx.set_verify(SSL.VERIFY_NONE)
        ctx.set_options(_util.lib.SSL_OP_TLS_ROLLBACK_BUG)
        conn = SSL.Connection(context=ctx, socket=self._transport.prepare_socket())
        if ssl.HAS_SNI:
            conn.set_tlsext_host_name(idna.encode(self._state.hostname))
        try:
            conn.connect((self._state.hostname, self._state.port))
        except SSL.Error as err:
            if "tlsv1 alert inappropriate fallback" in str(err):
                self._supports_fallback_scsv = True
        except ConnectionError:  # F5 result, possible false positive
            self._supports_fallback_scsv = True
        except TimeoutError:  # good indication
            self._supports_fallback_scsv = True
        finally:
            conn.close()

        return self._supports_fallback_scsv
