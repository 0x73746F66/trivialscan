from ...transport import TLSTransport
from .. import BaseEvaluationTask

PFS_PROTOCOLS = ["ECDHE-RSA", "ECDHE-ECDSA", "DHE-RSA", "DHE-DSA"]


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        results = []
        for proto in PFS_PROTOCOLS:
            if proto in self.transport.store.tls_state.negotiated_cipher:
                results.append(proto)
        if len(results) > 0:
            self.substitution_metadata["reason"] = " ".join(results)
            return True

        self.substitution_metadata["reason"] = f"{self.transport.store.tls_state.negotiated_cipher} does not provide forward anonymity"
        return False
