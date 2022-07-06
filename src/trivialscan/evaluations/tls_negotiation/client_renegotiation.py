from ...transport import TLSTransport
from ...exceptions import EvaluationNotImplemented
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        # self.transport.store.tls_state.client_initiated_renegotiation
        raise EvaluationNotImplemented
