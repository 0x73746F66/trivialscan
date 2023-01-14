from typing import Union

from ...transport import TLSTransport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> Union[bool, None]:
        results = []
        compression = ["gzip", "bz", "deflate", "compress"]
        for state in self.transport.store.http_states:
            for method in compression:
                if state.header_exists(name="content-encoding", includes_value=method):
                    self.substitution_metadata["content_encoding"] = state.response_headers.get('content-encoding')
                    results.append(method)

        if len(results) > 0:
            self.substitution_metadata["reason"] = ", ".join(results) + " compression present"
            return True
        return False
