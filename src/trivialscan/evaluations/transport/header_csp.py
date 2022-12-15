from typing import Union

from ...transport import TLSTransport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> Union[bool, None]:
        missing = []
        results = []
        for state in self.transport.store.http_states:
            exists = "content-security-policy" in state.response_headers
            if not exists:
                missing.append(state.request_url)
            results.append(exists)
        if missing:
            self.substitution_metadata["missing_paths"] = missing
        return all(results)
