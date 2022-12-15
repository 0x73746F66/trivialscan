from ...transport import TLSTransport
from ... import constants
from .. import BaseEvaluationTask, EvaluationResult

__version__ = "4.0"


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        violations = set()
        for evaluation_result in self.transport.store.evaluations:
            evaluation_result: EvaluationResult
            if evaluation_result.result_level != constants.RESULT_LEVEL_FAIL:
                continue
            for compliance in evaluation_result.compliance:
                if (
                    __version__ != compliance["version"]
                    or "PCI DSS" != compliance["compliance"]
                ):
                    continue
                violations.add(compliance["requirement"])

        self.substitution_metadata[f"PCI DSS {__version__} violations"] = list(
            violations
        )
        return len(violations) == 0
