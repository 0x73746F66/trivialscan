from typing import Union
from ...constants import WEAK_DNSSEC_ALGORITHMS
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
        if not isinstance(certificate, LeafCertificate) or not certificate.dnssec:
            raise EvaluationNotRelevant
        return (  # pylint: disable=consider-iterating-dictionary
            certificate.dnssec_algorithm in WEAK_DNSSEC_ALGORITHMS.keys()
        )
