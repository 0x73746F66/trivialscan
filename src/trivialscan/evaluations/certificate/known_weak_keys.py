from ...constants import KNOWN_WEAK_KEYS, WEAK_KEY_SIZE
from ...transport import Transport
from ...certificate import BaseCertificate
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        self.substitution_metadata["reason"] = KNOWN_WEAK_KEYS.get(
            certificate.public_key_type
        )
        self.substitution_metadata["public_key_type"] = certificate.public_key_type
        self.substitution_metadata["public_key_size"] = certificate.public_key_size
        return (
            certificate.public_key_type in KNOWN_WEAK_KEYS
            and certificate.public_key_size
            <= WEAK_KEY_SIZE[certificate.public_key_type]
        )