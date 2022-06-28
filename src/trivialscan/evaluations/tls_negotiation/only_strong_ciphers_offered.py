from ...constants import NOT_KNOWN_WEAK_CIPHERS
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        results = set()
        for offered_cipher in self._transport.state.offered_ciphers:
            if offered_cipher in NOT_KNOWN_WEAK_CIPHERS:
                results.add(offered_cipher)

        self.substitution_metadata["offered_strong_ciphers"] = " ".join(results)
        return len(results) > 0
