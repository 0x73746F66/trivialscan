from ...exceptions import EvaluationNotRelevant
from ...transport import Transport
from ...certificate import BaseCertificate
from ...constants import RSA_PUBLIC_EXPONENT_CONSTANT
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        if certificate.public_key_type != "RSA":
            raise EvaluationNotRelevant
        self.substitution_metadata[
            "public_key_exponent"
        ] = certificate.public_key_exponent
        return certificate.public_key_exponent != RSA_PUBLIC_EXPONENT_CONSTANT
