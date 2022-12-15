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
                results.append(
                    state.header_exists(name="content-encoding", includes_value=method)
                )

        return any(results)
