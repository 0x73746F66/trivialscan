import logging
from os import path
from datetime import timedelta
from requests_cache import CachedSession
from requests import Response
from requests.exceptions import SSLError
from urllib3.util.ssl_match_hostname import CertificateError
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

    @property
    def response_status(self) -> dict | None:
        return self._response.status_code

    @property
    def response_headers(self) -> dict | None:
        return {k: v for k, v in self._response.headers.items()}

    @property
    def response_text(self) -> str | None:
        return self._response.text

    @property
    def response_json(self) -> dict | list | None:
        return self._response.json()

    def do_request(self, http_request_path: str) -> bool:
        self._response = None
        self._session = CachedSession(
            path.join(
                self._configuration.get("tmp_path_prefix", "/tmp"), "trivialscan"
            ),
            backend="filesystem",
            use_temp=True,
            expire_after=timedelta(minutes=15),
        )
        self.skip = self._deny_robots(http_request_path)
        if self.skip:
            return False
        self._response = self._do_request(
            http_request_path,
            "GET",
            headers={"user-agent": "pypi.org/project/trivialscan"},
        )
        if self._response:
            url = f"https://{self._transport.state.hostname}:{self._transport.state.port}{http_request_path}"
            logger.info(f"{url} from cache {self._response.from_cache}")
            logger.debug(self._response.text)
            return True
        return False

    def _deny_robots(self, http_request_path: str) -> bool:
        head_response = self._do_request(
            "/robots.txt", headers={"user-agent": "pypi.org/project/trivialscan"}
        )
        if not head_response or head_response.status_code != 200:
            return False
        response = self._do_request(
            "/robots.txt", "GET", headers={"user-agent": "pypi.org/project/trivialscan"}
        )
        if response.status_code != 200:
            return False
        return self._parse_robots_path(response.text, http_request_path)

    def _parse_robots_path(self, contents: str, http_request_path: str) -> bool:
        track = False
        trail_slash = http_request_path[len(http_request_path) - 1 :] == "/"
        for line in contents.splitlines():
            trim_path = http_request_path[: len(http_request_path) - 1].strip()
            if track:
                if not line.startswith("Disallow:"):
                    track = False
                else:
                    disallow = line.replace("Disallow:", "").strip()
                    if (
                        trail_slash and trim_path and disallow == trim_path
                    ) or disallow == http_request_path:
                        return True
            if line.startswith("User-agent:") and "trivialscan" in line:
                track = True
                continue
            if line == "User-agent: *":
                track = True
                continue
        return False

    def _do_request(
        self, req_path: str, method: str = "HEAD", headers: dict = None
    ) -> Response | None:
        url = f"https://{self._transport.state.hostname}:{self._transport.state.port}{req_path}"
        try:
            return self._session.request(method, url, headers=headers)
        except (SSLError, ConnectionError, CertificateError):
            return None

    def header_exists(self, name: str, includes_value: str) -> bool:
        return (
            name in self._response.headers
            and includes_value in self._response.headers[name]
        )
