from ...exceptions import EvaluationNotImplemented
from ...transport import TLSTransport
from .. import BaseEvaluationTask

__version__ = "4.0"


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        raise EvaluationNotImplemented
