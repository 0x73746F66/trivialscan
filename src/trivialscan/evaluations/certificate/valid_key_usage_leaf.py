from typing import Union

from ...exceptions import EvaluationNotRelevant
from ...transport import TLSTransport
from ...certificate import BaseCertificate, LeafCertificate
from ...util import key_usage_exists, gather_key_usages
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        if not isinstance(certificate, LeafCertificate):
            raise EvaluationNotRelevant
        validator_key_usage, validator_extended_key_usage = gather_key_usages(
            certificate.x509.to_cryptography()
        )
        self.substitution_metadata["key_usage"] = validator_key_usage
        self.substitution_metadata["extended_key_usage"] = validator_extended_key_usage
        return (
            key_usage_exists(certificate.x509.to_cryptography(), "digital_signature")
            and key_usage_exists(certificate.x509.to_cryptography(), "serverAuth")
            and (
                key_usage_exists(certificate.x509.to_cryptography(), "key_encipherment")
                or key_usage_exists(certificate.x509.to_cryptography(), "key_agreement")
            )
        )
