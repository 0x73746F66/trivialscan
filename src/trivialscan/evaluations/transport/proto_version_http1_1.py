import logging
from ...exceptions import EvaluationNotImplemented
from ...transport import Transport
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: Transport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> bool | None:
        raise EvaluationNotImplemented
