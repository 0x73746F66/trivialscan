from ...exceptions import EvaluationNotRelevant
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> bool | None:
        if not self.transport.state.certificate_mtls_expected:
            raise EvaluationNotRelevant
        return self.transport.client_certificate_trusted
