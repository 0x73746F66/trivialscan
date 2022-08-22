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
            self._sync_script(state)
            self._sync_xhr(state)
            self._document_domain(state)

        if self._missing:
            self.substitution_metadata["missing_paths"] = list(set(self._missing))
        return all(self._results)

    def _sync_script(self, state: HTTPState):
        exists = (
            "permissions-policy" in state.response_headers
            and state.header_exists(
                name="permissions-policy", includes_value="sync-script=()"
            )
        ) or (
            "feature-policy" in state.response_headers
            and state.header_exists(
                name="feature-policy", includes_value="sync-script 'none'"
            )
        )
        if not exists:
            self._missing.append(state.request_url)
        self._results.append(exists)

    def _sync_xhr(self, state: HTTPState):
        exists = (
            "permissions-policy" in state.response_headers
            and state.header_exists(
                name="permissions-policy", includes_value="sync-xhr=()"
            )
        ) or (
            "feature-policy" in state.response_headers
            and state.header_exists(
                name="feature-policy", includes_value="sync-xhr 'none'"
            )
        )
        if not exists:
            self._missing.append(state.request_url)
        self._results.append(exists)

    def _document_domain(self, state: HTTPState):
        exists = (
            "permissions-policy" in state.response_headers
            and state.header_exists(
                name="permissions-policy", includes_value="document-domain=()"
            )
        ) or (
            "feature-policy" in state.response_headers
            and state.header_exists(
                name="feature-policy", includes_value="document-domain 'none'"
            )
        )
        if not exists:
            self._missing.append(state.request_url)
        self._results.append(exists)
