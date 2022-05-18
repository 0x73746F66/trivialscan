from ...constants import WEAK_DNSSEC_ALGORITHMS
from ...certificate import LeafCertificate
from ...transport import TransportState
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    _leaf_certificate: LeafCertificate

    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, state: TransportState, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, state, metadata, config)

    def _is_dnssec_valid(self) -> bool:
        for cert in self._state.certificates:
            if isinstance(cert, LeafCertificate):
                self._leaf_certificate = cert
                return cert.dnssec_valid
        return False

    def evaluate(self) -> bool | None:
        if self._is_dnssec_valid():
            return (  # pylint: disable=consider-iterating-dictionary
                self._leaf_certificate.dnssec_algorithm in WEAK_DNSSEC_ALGORITHMS.keys()
            )

        return None
