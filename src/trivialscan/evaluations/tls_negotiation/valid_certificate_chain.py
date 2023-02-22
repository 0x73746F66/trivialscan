import logging
from typing import Union

from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from certvalidator.errors import (
    PathValidationError,
    RevokedError,
    InvalidCertificateError,
    PathBuildingError,
)

from ...exceptions import EvaluationNotRelevant
from ...util import validate_certificate_chain, gather_key_usages
from ...certificate import LeafCertificate
from ...transport import TLSTransport
from .. import BaseEvaluationTask

logger = logging.getLogger(__file__)
RESULT_KEY = "chain_validation_result"


class EvaluationTask(BaseEvaluationTask):
    _leaf_certificate: LeafCertificate

    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> Union[bool, None]:  # pylint: disable=arguments-differ
        leaf = None
        for cert in self.transport.store.tls_state.certificates:
            if isinstance(cert, LeafCertificate):
                leaf = cert
                break
        if not leaf:
            raise EvaluationNotRelevant

        validator_key_usage, validator_extended_key_usage = gather_key_usages(
            leaf.x509.to_cryptography()
        )
        self.substitution_metadata["key_usage"] = validator_key_usage
        self.substitution_metadata["extended_key_usage"] = validator_extended_key_usage
        try:
            validate_certificate_chain(
                dump_certificate(FILETYPE_PEM, leaf.x509),
                self.transport._certificate_chain,  # pylint: disable=protected-access
                validator_key_usage,
                validator_extended_key_usage,
            )
        except (
            RevokedError,
            InvalidCertificateError,
            PathValidationError,
            PathBuildingError,
        ) as ex:
            self.substitution_metadata[RESULT_KEY] = str(ex)
            return False
        except Exception as ex:
            logger.debug(ex, exc_info=True)
            self.substitution_metadata[RESULT_KEY] = str(ex)
            self.substitution_metadata[
                "reason"
            ] = "An unexpected exception occurred during chain verification"
            return False

        self.substitution_metadata[
            RESULT_KEY
        ] = f'Validated: {",".join(validator_key_usage + validator_extended_key_usage)}'
        return True
