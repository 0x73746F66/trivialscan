import logging
import csv
from os import path
from datetime import timedelta
from contextlib import closing
from io import StringIO
from typing import Union

from requests_cache import CachedSession

from ...constants import COMPROMISED_SHA1
from ...transport import TLSTransport
from ...certificate import BaseCertificate
from .. import BaseEvaluationTask

REMOTE_CSV = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
ABUSESH_LOOKUP: dict[str, dict[str, str]] = {}
logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    probe_info: str = REMOTE_CSV

    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)
        self._session = CachedSession(
            path.join(config.get("tmp_path_prefix", "/tmp"), "abuse.sh"),
            backend="filesystem",
            use_temp=True,
            expire_after=timedelta(minutes=5),
        )

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        self.substitution_metadata["sha1_fingerprint"] = certificate.sha1_fingerprint
        if certificate.sha1_fingerprint.upper() in COMPROMISED_SHA1:
            self.substitution_metadata["reason"] = COMPROMISED_SHA1[
                certificate.sha1_fingerprint.upper()
            ]
            return True
        self.substitution_metadata["abuse.sh"] = self.abuse(
            certificate.sha1_fingerprint
        )
        if isinstance(self.substitution_metadata["abuse.sh"], dict):
            self.substitution_metadata["reason"] = self.substitution_metadata[
                "abuse.sh"
            ]["reason"]
            return True
        return False

    def abuse(self, sha1_fingerprint) -> Union[dict, bool]:
        if not ABUSESH_LOOKUP:
            with closing(
                self._session.get(REMOTE_CSV, stream=True, allow_redirects=True)
            ) as raw:
                logger.info(f"{REMOTE_CSV} from cache {raw.from_cache}")
                logger.debug(raw.text)
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
