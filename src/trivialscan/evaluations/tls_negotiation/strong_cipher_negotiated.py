from ...constants import NOT_KNOWN_WEAK_CIPHERS
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: Transport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        return self._transport.state.negotiated_cipher in NOT_KNOWN_WEAK_CIPHERS
