from typing import Union

from ...constants import OCSP_STATUS_REASON_MAP
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
        if not isinstance(certificate, LeafCertificate):
            raise EvaluationNotRelevant
        self.substitution_metadata[
            "revocation_ocsp_status"
        ] = certificate.revocation_ocsp_status
        self.substitution_metadata[
            "revocation_ocsp_detail"
        ] = OCSP_STATUS_REASON_MAP.get(certificate.revocation_ocsp_status)
        self.substitution_metadata[
            "revocation_ocsp_time"
        ] = certificate.revocation_ocsp_time
        self.substitution_metadata[
            "revocation_ocsp_response"
        ] = certificate.revocation_ocsp_response
        self.substitution_metadata[
            "revocation_ocsp_reason"
        ] = certificate.revocation_ocsp_reason
        return certificate.revocation_ocsp_result
