from ...transport import TransportState
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, state: TransportState, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, state, metadata, config)

    def evaluate(self):
        results = []
        for offered_cipher in self._state.offered_ciphers:
            results.append("-CBC-" in offered_cipher)

        return any(results)
