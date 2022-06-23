from tlstrust import TrustStore, context
from ...exceptions import EvaluationNotRelevant
from ...transport import Transport
from ...certificate import BaseCertificate, RootCertificate
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        if not isinstance(certificate, RootCertificate):
            raise EvaluationNotRelevant

        return TrustStore(certificate.subject_key_identifier).check_trust(
            context_type=context.PLATFORM_ANDROID9
        )
