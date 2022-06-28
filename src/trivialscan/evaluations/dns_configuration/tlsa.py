from ...exceptions import EvaluationNotRelevant
from ...certificate import LeafCertificate
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> bool:
        for cert in self._transport.state.certificates:
            if isinstance(cert, LeafCertificate):
                return cert.tlsa
        raise EvaluationNotRelevant