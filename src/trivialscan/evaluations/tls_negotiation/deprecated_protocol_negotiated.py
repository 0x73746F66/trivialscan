from ...constants import WEAK_PROTOCOL
from ...transport import TransportState
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(
        self, transport: Transport, state: TransportState, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, state, metadata, config)

    def evaluate(self):
        return self._state.negotiated_protocol in WEAK_PROTOCOL.keys()
