from ..transport import TransportState
from ..transport import Transport


class BaseEvaluationTask:
    _transport: Transport
    _metadata: dict
    substitution_metadata: dict

    def __init__(
        self,
        transport: Transport,
        metadata: dict,
        configuration: dict,
    ) -> None:
        self._transport = transport
        self._metadata = metadata
        self._configuration = configuration
        self.substitution_metadata = {}


    @property
    def transport(self) -> Transport:
        return self._transport


    @property
    def state(self) -> TransportState:
        return self._transport.get_state()


    @property
    def metadata(self) -> dict:
        return self._metadata
