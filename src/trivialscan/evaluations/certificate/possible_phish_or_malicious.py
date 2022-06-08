import logging
import csv
from os import path
from datetime import timedelta
from contextlib import closing
from io import StringIO
from requests_cache import CachedSession
from ...constants import COMPROMISED_SHA1
from ...transport import TransportState
from ...transport import Transport
from .. import BaseEvaluationTask

REMOTE_CSV = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
ABUSESH_LOOKUP: dict[str, dict[str, str]] = {}
logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: Transport, state: TransportState, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, state, metadata, config)
        self._session = CachedSession(
            path.join(config.get("tmp_path_prefix", "/tmp"), "abuse.sh"),
            backend="filesystem",
            use_temp=True,
            expire_after=timedelta(minutes=5),
        )

    def evaluate(self) -> bool | None:
        for cert in self._state.certificates:
            self.substitution_metadata["abuse.sh"] = self.abuse(cert.sha1_fingerprint)
            self.substitution_metadata["sha1_fingerprint"] = cert.sha1_fingerprint
            if (
                cert.sha1_fingerprint.upper() in COMPROMISED_SHA1.keys()
            ):  # pylint: disable=consider-iterating-dictionary
                self.substitution_metadata["reason"] = COMPROMISED_SHA1[
                    cert.sha1_fingerprint.upper()
                ]
                return True
            if isinstance(self.substitution_metadata["abuse.sh"], dict):
                self.substitution_metadata["reason"] = self.substitution_metadata[
                    "abuse.sh"
                ]["reason"]
                return True
        return False

    def abuse(self, sha1_fingerprint) -> dict | bool:
        if not ABUSESH_LOOKUP:
            with closing(
                self._session.get(REMOTE_CSV, stream=True, allow_redirects=True)
            ) as raw:
                logger.info(f"{REMOTE_CSV} from cache {raw.from_cache}")
                buff = StringIO(raw.text)
            for item in csv.reader(
                filter(lambda row: row[0] != "#", buff), delimiter=",", quotechar='"'
            ):
                if len(item) != 3:
                    continue
                date_added, fingerprint, reason = item
                ABUSESH_LOOKUP[fingerprint] = {
                    "date_added": date_added,
                    "reason": reason,
                }
        return ABUSESH_LOOKUP.get(sha1_fingerprint, False)
