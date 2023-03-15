from OpenSSL import SSL
from ...constants import OPENSSL_VERSION_LOOKUP
from ...transport import TLSTransport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)
        self._renegotiation_info_scsv = None

    def evaluate(self):
        self._renegotiation_info_scsv = (
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
            in self.transport.store.tls_state.offered_ciphers
        )
        if not self._renegotiation_info_scsv:
            self.substitution_metadata[
                "reason"
            ] = "Missing pseudo cipher TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        # no downgrade possible using TLS 1.3
        if not self._renegotiation_info_scsv and all(
            [
                self.transport.store.tls_state.preferred_protocol
                == OPENSSL_VERSION_LOOKUP[SSL.TLS1_3_VERSION],
                self.transport.store.tls_state.negotiated_protocol
                == OPENSSL_VERSION_LOOKUP[SSL.TLS1_3_VERSION],
            ]
        ):
            self.substitution_metadata[
                "reason"
            ] = "Downgrade not possible after successful negotiation of TLS 1.3"
            self._renegotiation_info_scsv = True

        return self._renegotiation_info_scsv
