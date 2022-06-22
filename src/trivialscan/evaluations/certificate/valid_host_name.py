from ...transport import Transport
from ...certificate import BaseCertificate, LeafCertificate
from ...util import match_hostname
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        if not isinstance(certificate, LeafCertificate):
            return None
        return match_hostname(
            self.transport.state.hostname, certificate.x509.to_cryptography()
        )
