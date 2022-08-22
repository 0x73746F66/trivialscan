from typing import Union

from ...exceptions import EvaluationNotRelevant
from ...transport import TLSTransport
from ...certificate import BaseCertificate
from ...constants import RSA_PUBLIC_EXPONENT_CONSTANT
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        if certificate.public_key_type != "RSA":
            raise EvaluationNotRelevant
        self.substitution_metadata[
            "public_key_exponent"
        ] = certificate.public_key_exponent
        return certificate.public_key_exponent < RSA_PUBLIC_EXPONENT_CONSTANT
