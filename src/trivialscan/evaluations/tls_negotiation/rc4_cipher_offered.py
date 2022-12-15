from ...transport import TLSTransport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        results = set()
        for offered_cipher in self.transport.store.tls_state.offered_ciphers:
            if "RC4" in offered_cipher:
                results.add(offered_cipher)

        self.substitution_metadata["offered_rc4_ciphers"] = " ".join(results)
        return len(results) > 0
