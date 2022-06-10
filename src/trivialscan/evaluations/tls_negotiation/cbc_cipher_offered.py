from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        state = self._transport.get_state()
        results = []
        for offered_cipher in state.offered_ciphers:
            results.append("-CBC-" in offered_cipher)

        return any(results)
