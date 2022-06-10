from ...certificate import LeafCertificate
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: Transport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> bool | None:
        for cert in self._transport.get_state().certificates:
            if isinstance(cert, LeafCertificate):
                return cert.dnssec_valid
        return None
