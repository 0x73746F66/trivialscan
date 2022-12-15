from typing import Union

from ...exceptions import EvaluationNotRelevant
from ...transport import TLSTransport
from ...certificate import BaseCertificate, LeafCertificate
from ...util import extract_from_subject, validate_common_name
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        if not certificate.subject:
            return False
        common_name = extract_from_subject(certificate.x509.to_cryptography())
        if not common_name:
            return False
        self.substitution_metadata["common_name"] = common_name
        if not isinstance(certificate, LeafCertificate):
            raise EvaluationNotRelevant
        return validate_common_name(
            common_name, self.transport.store.tls_state.hostname
        )
