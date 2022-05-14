from ..transport import TransportState
from ..transport import Transport


class BaseEvaluationTask:
    _transport: Transport
    _state: TransportState
    _metadata: dict

    def __init__(
        self,
        transport: Transport,
        state: TransportState,
        metadata: dict,
        configuration: dict,
    ) -> None:
        self._transport = transport
        self._state = state
        self._metadata = metadata
        self._configuration = configuration
