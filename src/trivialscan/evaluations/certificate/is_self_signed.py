from typing import Union
from ...exceptions import EvaluationNotRelevant
from ...transport import TLSTransport
from ...certificate import BaseCertificate, RootCertificate
from ...util import is_self_signed
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        if isinstance(certificate, RootCertificate) and certificate.trust_stores:
            raise EvaluationNotRelevant
        return is_self_signed(certificate.x509.to_cryptography())
