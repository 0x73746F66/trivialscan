from typing import Union

from ...exceptions import EvaluationNotRelevant
from ...transport import TLSTransport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> Union[bool, None]:
        if not self.transport.store.tls_state.certificate_mtls_expected:
            raise EvaluationNotRelevant
        return self.transport.store.tls_state.client_certificate_match
