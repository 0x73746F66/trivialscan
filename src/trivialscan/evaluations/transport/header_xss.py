from typing import Union

from ...transport import TLSTransport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> Union[bool, None]:
        issues = []
        results = []
        for state in self.transport.store.http_states:
            misconfiguration = state.header_exists(
                name="x-xss-protection"
            ) and not state.header_exists(name="x-xss-protection", includes_value="0")
            if misconfiguration:
                issues.append(state.request_url)
            results.append(misconfiguration)
        if issues:
            self.substitution_metadata["misconfigured_paths"] = issues
        return any(results)
