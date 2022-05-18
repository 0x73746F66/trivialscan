from ...constants import KNOWN_WEAK_SIGNATURE_ALGORITHMS
from ...transport import TransportState
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, state: TransportState, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, state, metadata, config)

    def evaluate(self) -> bool | None:
        results: list[bool] = []
        for cert in self._state.certificates:
            results.append(
                cert.signature_algorithm in KNOWN_WEAK_SIGNATURE_ALGORITHMS.keys()
            )  # pylint: disable=consider-iterating-dictionary
        return any(results)
