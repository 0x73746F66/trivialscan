from ...util import caa_valid
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
        if not isinstance(certificate, LeafCertificate):
            raise EvaluationNotRelevant
        return caa_valid(
            self.transport.state.hostname,
            certificate.x509,
            self.transport.certificate_chain,
        )