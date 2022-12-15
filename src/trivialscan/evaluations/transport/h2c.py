import logging
import socket
import ssl
from typing import Union

from h2.connection import H2Connection

from ...transport import TLSTransport
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    probe_info: str = "Protocol HTTP/2"

    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self) -> Union[bool, None]:
        results = []
        for state in self.transport.store.http_states:
            try:
                connection = ssl.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    ssl_version=ssl.PROTOCOL_TLS,
                )
                connection.settimeout(3)
            except Exception as ex:
                logger.warning(ex, exc_info=True)
                continue
            try:
                connection.connect(
                    (
                        self.transport.store.tls_state.hostname,
                        self.transport.store.tls_state.port,
                    )
                )
                addl_conn_str = b", HTTP2-Settings"
                request = (
                    b"GET "
                    + state.request_url.encode()
                    + b" HTTP/1.1\r\n"
                    + b"Host: "
                    + self.transport.store.tls_state.hostname.encode()
                    + b"\r\n"
                    + b"Accept: */*\r\n"
                    + b"Accept-Language: en\r\n"
                    + b"Upgrade: h2c\r\n"
                    + b"HTTP2-Settings: "
                    + b"AAMAAABkAARAAAAAAAIAAAAA"
                    + b"\r\n"
                    + b"Connection: Upgrade"
                    + addl_conn_str
                    + b"\r\n"
                    + b"\r\n"
                )
                connection.sendall(request)
                h2_connection = H2Connection()
                h2_connection.initiate_upgrade_connection()
                _, success = self.get_upgrade_response(connection)
                results.append(success)

            except Exception as ex:
                logger.warning(ex, exc_info=True)
                continue
            finally:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                    connection.close()
                except Exception as ex:
                    logger.debug(ex, exc_info=True)

        return any(results)

    def get_upgrade_response(self, connection):
        data = b""
        while b"\r\n\r\n" not in data:
            data += connection.recv(8192)
        headers, rest = data.split(b"\r\n\r\n", 1)
        # An upgrade response begins HTTP/1.1 101 Switching Protocols.
        split_headers = headers.split()
        if split_headers[1] != b"101":
            logger.debug("Failed to upgrade")
            return None, False

        return rest, True
