from ...constants import NOT_KNOWN_WEAK_CIPHERS
from ...transport import TLSTransport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        results = []
        for offered_cipher in self.transport.store.tls_state.offered_ciphers:
            if offered_cipher in NOT_KNOWN_WEAK_CIPHERS:
                results.append(offered_cipher)

        self.substitution_metadata["offered_strong_ciphers"] = " ".join(results)
        return len(results) > 0
