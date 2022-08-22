from typing import Union

from ...transport import TLSTransport, HTTPState
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)
        self._missing = []
        self._results = []

    def evaluate(self) -> Union[bool, None]:
        for state in self.transport.store.http_states:
            self._clipboard_read(state)

        if self._missing:
            self.substitution_metadata["missing_paths"] = list(set(self._missing))
        return all(self._results)

    def _clipboard_read(self, state: HTTPState):
        exists = (
            "permissions-policy" in state.response_headers
            and state.header_exists(
                name="permissions-policy", includes_value="clipboard-read=()"
            )
        ) or (
            "feature-policy" in state.response_headers
            and state.header_exists(
                name="feature-policy", includes_value="clipboard-read 'none'"
            )
        )
        if not exists:
            self._missing.append(state.request_url)
        self._results.append(exists)
