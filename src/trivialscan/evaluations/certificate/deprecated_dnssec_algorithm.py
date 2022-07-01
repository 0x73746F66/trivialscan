from ...constants import WEAK_DNSSEC_ALGORITHMS
from ...exceptions import EvaluationNotRelevant
from ...transport import Transport
from ...certificate import BaseCertificate, LeafCertificate
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        if not isinstance(certificate, LeafCertificate) or not certificate.dnssec_valid:
            raise EvaluationNotRelevant
        return (  # pylint: disable=consider-iterating-dictionary
            certificate.dnssec_algorithm in WEAK_DNSSEC_ALGORITHMS.keys()
        )
