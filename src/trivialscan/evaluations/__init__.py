import logging
from requests_cache import CachedSession
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
