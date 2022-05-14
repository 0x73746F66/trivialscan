import logging
import requests
from ...transport import TransportState
from ...transport import Transport
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    def __init__(
        self, transport: Transport, state: TransportState, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, state, metadata, config)
        self._result = None

    def evaluate(self):
        if isinstance(self._result, bool):
            return self._result

        results: list[bool] = []
        for cert in self._state.certificates:
            url = f"https://v1.pwnedkeys.com/{cert.spki_fingerprint.lower()}.jws"
            logger.info(f"Check {url}")
            resp = requests.get(url)
            logger.debug(resp.text)
            if "That key does not appear to be pwned" in resp.text:
                results.append(False)
            if resp.status_code == 200:
                results.append(True)

        self._result = any(results)
        return self._result
