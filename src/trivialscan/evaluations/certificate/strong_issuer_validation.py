from ...constants import VALIDATION_OID
from ...exceptions import NoLogEvaluation
from ...transport import Transport
from ...certificate import BaseCertificate
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        validation_level = VALIDATION_OID.get(certificate.validation_oid)
        if not validation_level:
            raise NoLogEvaluation
        return validation_level != "DV"
