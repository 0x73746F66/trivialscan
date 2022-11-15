import logging
from dataclasses import dataclass
from typing import Union

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
    probe_info: Union[str, None] = None

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

    def evaluate(self, certificate: BaseCertificate) -> Union[bool, None]:
        raise NotImplementedError


@dataclass
class EvaluationResult:
    rule_id: int
    name: str
    key: str
    group_id: int
    group: str
    result_value: Union[str, None, bool]
    result_label: str
    description: str
    metadata: dict[str, str]
    cve: Union[list[str], None] = None
    cvss2: Union[str, None] = None
    cvss3: Union[str, None] = None
    references: Union[list[dict[str, str]], None] = None
    compliance: Union[dict, None] = None
    threats: Union[dict, None] = None
    result_color: Union[str, None] = None
    result_text: str = constants.RESULT_LEVEL_INFO_DEFAULT
    result_level: str = constants.RESULT_LEVEL_INFO
    score: int = 0
