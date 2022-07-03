from cryptography.x509 import Name, NameOID
from ...constants import VALIDATION_OID, QUESTIONABLE_DV_ISSUERS
from ...exceptions import NoLogEvaluation
from ...transport import TLSTransport
from ...certificate import BaseCertificate
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        validation_level = VALIDATION_OID.get(certificate.validation_oid)
        if not validation_level:
            raise NoLogEvaluation
        if validation_level != "DV":
            return False
        common_name = (
            Name.from_rfc4514_string(certificate.issuer)
            .get_attributes_for_oid(NameOID.COMMON_NAME)[0]
            .value
        )
        return common_name in QUESTIONABLE_DV_ISSUERS
