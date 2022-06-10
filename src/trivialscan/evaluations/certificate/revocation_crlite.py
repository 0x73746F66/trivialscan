from os import path
from ... import util
from ...transport import Transport
from ...certificate import BaseCertificate
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(self, transport: Transport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self, certificate: BaseCertificate):
        tmp_path_prefix = self._configuration.get("tmp_path_prefix", "/tmp")
        return util.crlite_revoked(
            db_path=path.join(tmp_path_prefix, ".crlite_db"),
            pem=certificate.pem.encode(),
        )
