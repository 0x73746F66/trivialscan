import logging
from typing import Union

from ...exceptions import EvaluationNotRelevant
from ...transport import TLSTransport
from ...certificate import BaseCertificate, LeafCertificate
from ...util import match_hostname
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        if not isinstance(certificate, LeafCertificate):
            raise EvaluationNotRelevant
        try:
            if not match_hostname(
                self.transport.store.tls_state.hostname,
                certificate.x509.to_cryptography(),
            ):
                self.substitution_metadata[
                    "reason"
                ] = "Hostname is invalid and no match found in Subject Alternative Names"
                return False
        except ValueError as err:
            self.substitution_metadata["reason"] = str(err)
            return False
        except Exception as ex:
            logger.debug(ex, exc_info=True)
            self.substitution_metadata[
                "reason"
            ] = "An unhandled exception occurred reading the leaf Certificate information"
            return None
        return True
