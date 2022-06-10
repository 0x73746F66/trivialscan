from ...constants import NOT_KNOWN_WEAK_CIPHERS
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        results = []
        for offered_cipher in self._transport.get_state().offered_ciphers:
            results.append(offered_cipher not in NOT_KNOWN_WEAK_CIPHERS)

        return any(results)
