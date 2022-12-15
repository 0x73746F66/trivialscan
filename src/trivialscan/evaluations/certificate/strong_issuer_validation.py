import logging
from typing import Union

from ...constants import VALIDATION_OID
from ...exceptions import NoLogEvaluation, EvaluationNotRelevant
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
        if isinstance(certificate, RootCertificate):
            raise EvaluationNotRelevant
        validation_level = VALIDATION_OID.get(certificate.validation_oid)
        if not validation_level:
            reason = f"Unknown Certificate validation OID {certificate.validation_oid}"
            logger.warning(reason)
            self.substitution_metadata["reason"] = reason
            raise NoLogEvaluation
        return validation_level != "DV"
