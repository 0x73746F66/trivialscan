from ...certificate import LeafCertificate
from ...transport import TransportState
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(
        self, transport: Transport, state: TransportState, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, state, metadata, config)

    def evaluate(self) -> bool | None:
        for cert in self._state.certificates:
            if isinstance(cert, LeafCertificate):
                return cert.dnssec_valid
        return None
