import logging
from os import path
from datetime import timedelta
from requests_cache import CachedSession
from requests import Response
from ..transport import TransportState
from ..transport import Transport

logger = logging.getLogger(__name__)


class BaseEvaluationTask:
    _response: Response
    _session: CachedSession
    _transport: Transport
    _metadata: dict
    substitution_metadata: dict
    skip: bool

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
        self.skip = False

    @property
    def transport(self) -> Transport:
        return self._transport

    @property
    def state(self) -> TransportState:
        return self._transport.state

    @property
    def metadata(self) -> dict:
        return self._metadata

    def do_request(self, http_request_path: str):
        self._response = None
        self._session = CachedSession(
            path.join(
                self._configuration.get("tmp_path_prefix", "/tmp"), "trivialscan"
            ),
            backend="filesystem",
            use_temp=True,
            expire_after=timedelta(minutes=15),
        )
        self.skip = self._check_robots(http_request_path)
        if self.skip:
            return
        self._response = self._do_request(
            http_request_path,
            "GET",
            headers={"user-agent": "pypi.org/project/trivialscan"},
        )
        if self._response:
            url = f"https://{self._transport.state.hostname}:{self._transport.state.port}{http_request_path}"
            logger.info(f"{url} from cache {self._response.from_cache}")
            logger.debug(self._response.text)
            return
        self.skip = True

    def _check_robots(self, http_request_path: str) -> bool:
        head_response = self._do_request(
            "/robots.txt", headers={"user-agent": "pypi.org/project/trivialscan"}
        )
        if not head_response or head_response.status_code != 200:
            return True
        response = self._do_request(
            "/robots.txt", "GET", headers={"user-agent": "pypi.org/project/trivialscan"}
        )
        if response.status_code != 200:
            return True
        return self._parse_robots_path(response.text, http_request_path)

    def _parse_robots_path(self, contents: str, http_request_path: str) -> bool:
        track = False
        for line in contents.splitlines():
            if track and line.startswith("Disallow:"):
                if line.replace("Disallow:", "").strip().startswith(http_request_path):
                    return False
            if line.startswith("User-agent: trivialscan"):
                track = True
                continue
            if line.startswith("User-agent: *"):
                track = True
                continue
            track = False
        return True

    def _do_request(
        self, req_path: str, method: str = "HEAD", headers: dict = None
    ) -> Response | None:
        url = f"https://{self._transport.state.hostname}:{self._transport.state.port}{req_path}"
        try:
            return self._session.request(method, url, headers=headers)
        except ConnectionError:
            return None
