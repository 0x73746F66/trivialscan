import logging
from ...transport import Transport
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: Transport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> bool | None:
        return any(
            [
                self.header_exists(name="content-encoding", includes_value="gzip"),
                self.header_exists(name="content-encoding", includes_value="compress"),
                self.header_exists(name="content-encoding", includes_value="deflate"),
                self.header_exists(name="content-encoding", includes_value="br"),
            ]
        )

    def header_exists(self, name: str, includes_value: str) -> bool:
        return (
            name in self._response.headers
            and includes_value in self._response.headers[name]
        )
