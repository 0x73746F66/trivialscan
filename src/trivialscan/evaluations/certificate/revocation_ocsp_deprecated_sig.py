from typing import Union

from ...constants import DEPRECATED_OCSP_ALGO
from ...exceptions import EvaluationNotRelevant
from ...transport import TLSTransport
from ...certificate import BaseCertificate, LeafCertificate
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        if not isinstance(certificate, LeafCertificate):
            raise EvaluationNotRelevant
        if not certificate.revocation_ocsp_signature_hash_algorithm:
            return None
        return (
            certificate.revocation_ocsp_signature_hash_algorithm.upper()
            in DEPRECATED_OCSP_ALGO
        )
