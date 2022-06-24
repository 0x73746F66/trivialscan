from ...exceptions import EvaluationNotRelevant
from ...transport import Transport
from ...certificate import BaseCertificate, LeafCertificate
from .. import BaseEvaluationTask
from ...util import get_basic_constraints


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        if not isinstance(certificate, LeafCertificate):
            raise EvaluationNotRelevant
        ca, _ = get_basic_constraints(certificate.x509.to_cryptography())
        return ca
