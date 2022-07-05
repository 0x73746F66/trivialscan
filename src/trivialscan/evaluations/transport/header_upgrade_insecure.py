from ...transport import TLSTransport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> bool | None:
        missing = []
        results = []
        for state in self.transport.store.http_states:
            exists = (
                "content-security-policy" in state.response_headers
                and state.header_exists(
                    name="content-security-policy",
                    includes_value="upgrade-insecure-requests",
                )
                and "upgrade-insecure-requests" in state.response_headers
                and state.header_exists(
                    name="upgrade-insecure-requests",
                    includes_value="1",
                )
            )
            if not exists:
                missing.append(state.request_url)
            results.append(exists)
        if missing:
            self.substitution_metadata["missing_paths"] = list(set(missing))
        return all(results)
