import logging
from dataclasses import dataclass
from requests_cache import CachedSession
from .. import constants
from ..certificate import BaseCertificate
from ..transport import TLSTransport

logger = logging.getLogger(__name__)


class BaseEvaluationTask:
    _session: CachedSession
    transport: TLSTransport
    metadata: dict
    substitution_metadata: dict
    probe_info: str | None = None

    def __init__(
        self,
        transport: TLSTransport,
        metadata: dict,
        configuration: dict,
    ) -> None:
        self.transport = transport
        self.metadata = metadata
        self._configuration = configuration
        self.substitution_metadata = {}

    def evaluate(self, certificate: BaseCertificate) -> bool | None:
        raise NotImplementedError


@dataclass
class EvaluationResult:
    name: str
    key: str
    group: str
    result_value: str | None | bool
    result_label: str
    description: str
    metadata: dict[str, str]
    cve: list[str] | None = None
    cvss2: str | None = None
    cvss3: str | None = None
    references: list[dict[str, str]] | None = None
    compliance: dict | None = None
    threats: dict | None = None
    result_color: str | None = None
    result_text: str = constants.RESULT_LEVEL_INFO_DEFAULT
    result_level: str = constants.RESULT_LEVEL_INFO
    score: int = 0
