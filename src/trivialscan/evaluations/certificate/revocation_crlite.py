from os import path
from ... import util
from ...transport import TransportState
from ...transport import Transport
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(
        self, transport: Transport, state: TransportState, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, state, metadata, config)
        self._result = None

    def evaluate(self):
        if isinstance(self._result, bool):
            return self._result

        tmp_path_prefix = self._configuration["defaults"].get("tmp_path_prefix", "/tmp")
        results: list[bool] = []
        for cert in self._state.certificates:
            results.append(
                util.crlite_revoked(
                    db_path=path.join(tmp_path_prefix, ".crlite_db"),
                    pem=cert.pem.encode(),
                )
            )

        self._result = any(results)
        return self._result
