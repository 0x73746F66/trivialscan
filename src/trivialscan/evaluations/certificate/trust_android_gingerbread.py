import logging
from typing import Union

from tlstrust import TrustStore, context
from ...exceptions import EvaluationNotRelevant, NoLogEvaluation
from ...transport import TLSTransport
from ...certificate import BaseCertificate, RootCertificate
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        if not isinstance(certificate, RootCertificate):
            raise EvaluationNotRelevant
        if not certificate.subject_key_identifier:
            reason = f"Missing SKI RootCertificate {certificate.issuer_common_name}"
            logger.warning(reason)
            self.substitution_metadata["reason"] = reason
            raise NoLogEvaluation

        return TrustStore(certificate.subject_key_identifier).check_trust(
            context_type=context.PLATFORM_ANDROID2_3
        )
