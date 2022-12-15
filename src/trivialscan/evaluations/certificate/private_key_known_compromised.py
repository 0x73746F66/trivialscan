import logging
from os import path
from datetime import timedelta
from requests_cache import CachedSession
from requests.exceptions import ConnectionError
from ...transport import TLSTransport
from ...certificate import BaseCertificate
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)
BASE_URL = "https://v1.pwnedkeys.com"


class EvaluationTask(BaseEvaluationTask):
    probe_info: str = BASE_URL

    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)
        self._session = CachedSession(
            path.join(config.get("tmp_path_prefix", "/tmp"), "pwnedkeys.com"),
            backend="filesystem",
            use_temp=True,
            expire_after=timedelta(hours=1),
        )

    def evaluate(self, certificate: BaseCertificate):
        self.substitution_metadata["spki_fingerprint"] = certificate.spki_fingerprint
        url = f"{BASE_URL}/{certificate.spki_fingerprint.lower()}.jws"
        try:
            resp = self._session.get(url)
        except ConnectionError:
            return None
        logger.info(f"{url} from cache {resp.from_cache}")
        logger.debug(resp.text)
        if "That key does not appear to be pwned" in resp.text:
            return False
        if resp.status_code == 200:
            return True
        return None
