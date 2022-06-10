from ...constants import KNOWN_WEAK_SIGNATURE_ALGORITHMS
from ...transport import Transport
from ...certificate import BaseCertificate
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        self.substitution_metadata[
            "signature_algorithm"
        ] = certificate.signature_algorithm
        self.substitution_metadata["reason"] = KNOWN_WEAK_SIGNATURE_ALGORITHMS.get(
            certificate.signature_algorithm
        )
        return certificate.signature_algorithm in KNOWN_WEAK_SIGNATURE_ALGORITHMS
