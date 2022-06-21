from ...constants import WEAK_PROTOCOL
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: Transport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        return self._transport.state.negotiated_protocol in WEAK_PROTOCOL.keys()
