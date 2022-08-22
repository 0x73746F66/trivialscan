from typing import Union

from ...constants import SCT_GOOD, SCT_STATUS_MAP
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
            "certificate_transparency_description"
        ] = SCT_STATUS_MAP.get(certificate.transparency)
        return certificate.transparency == SCT_GOOD
