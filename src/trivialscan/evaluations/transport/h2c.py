from ...transport import TLSTransport
from ...exceptions import EvaluationNotImplemented
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> bool | None:
        raise EvaluationNotImplemented
