from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: Transport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        return any(
            [
                self._transport.header_exists(
                    name="content-encoding", includes_value="gzip"
                ),
                self._transport.header_exists(
                    name="content-encoding", includes_value="compress"
                ),
                self._transport.header_exists(
                    name="content-encoding", includes_value="deflate"
                ),
                self._transport.header_exists(
                    name="content-encoding", includes_value="br"
                ),
            ]
        )
