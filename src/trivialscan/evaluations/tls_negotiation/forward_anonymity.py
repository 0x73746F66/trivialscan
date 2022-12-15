from ...transport import TLSTransport
from .. import BaseEvaluationTask

PFS_PROTOCOLS = ["ECDHE-RSA", "ECDHE-ECDSA", "DHE-RSA" "DHE-DSA"]


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        results = []
        for proto in PFS_PROTOCOLS:
            results.append(proto in self.transport.store.tls_state.negotiated_cipher)
        return any(results)
