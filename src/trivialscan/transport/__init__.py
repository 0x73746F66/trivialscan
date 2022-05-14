import logging
import ssl
from datetime import datetime
from time import sleep
from socket import socket, AF_INET, SOCK_STREAM, MSG_PEEK
from pathlib import Path
from cryptography.x509 import extensions, oid
from cryptography.x509.base import Certificate
from cryptography.x509.ocsp import (
    OCSPResponse,
    load_der_ocsp_response,
    OCSPResponseStatus,
    OCSPCertStatus,
    OCSPRequestBuilder,
)
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import SSL, _util
from OpenSSL.SSL import _lib as native_openssl
from OpenSSL.crypto import X509, FILETYPE_PEM, X509Name, load_certificate
from certifi import where
from requests import post
import validators
import idna
from .. import exceptions, util, constants
from ..transport.state import TransportState

__module__ = "trivialscan.transport"
logger = logging.getLogger(__name__)


class Transport:
    _client_pem_path: str
    http2_response_frame: str
    http1_code: int
    http1_status: str
    http1_response_proto: str
    http1_headers: dict
    http1_1_code: int
    http1_1_status: str
    http1_1_response_proto: str
    http1_1_headers: dict
    session_cache_mode: str
    server_certificate: X509
    client_certificate: X509
    client_certificate_match: bool
    client_initiated_renegotiation: bool
    tls_downgrade: bool
    _cafiles: list
    verifier_errors: list[tuple[X509], int]
    expected_client_subjects: list[X509Name]
    tmp_path_prefix: str = "/tmp"
    _certificate_chain: list[X509]
    _default_connect_method: str = "SSLv23_METHOD"
    _default_connect_verify_mode: str = "VERIFY_NONE"
    _data_recv_size: int = 8096
    _depth: dict
    _state: TransportState

    def __init__(self, hostname: str, port: int = 443) -> None:
        if not isinstance(port, int):
            raise TypeError(
                f"provided an invalid type {type(port)} for port, expected int"
            )
        if validators.domain(hostname) is not True:
            raise ValueError(f"provided an invalid domain {hostname}")
        self._state = TransportState()
        self._state.hostname = hostname
        self._state.port = port
        self._state.offered_tls_versions = []
        self._state.offered_ciphers = []
        self._state.tls_version_interference_versions = []
        self._state.tls_version_intolerance_versions = []
        self._depth = {}
        self._client_pem_path = None
        self._cafiles = []
        self._certificate_chain = []
        self.server_certificate = None
        self.client_certificate = None
        self.client_certificate_match = None
        self.client_initiated_renegotiation = None
        self.certificates = []
        self.verifier_errors = []
        self.expected_client_subjects = []

    def get_state(self) -> TransportState:
        return self._state

    def pre_client_authentication_check(self, client_pem_path: str = None) -> bool:
        if not isinstance(self._state.port, int):
            raise TypeError(
                f"provided an invalid type {type(self._state.port)} for port, expected int"
            )
        if validators.domain(self._state.hostname) is not True:
            raise ValueError(f"provided an invalid domain {self._state.hostname}")
        if not isinstance(client_pem_path, str):
            raise TypeError(
                f"provided an invalid type {type(client_pem_path)} for client_pem_path, expected str"
            )

        self._state.certificate_mtls_expected = True
        self.client_certificate_match = False
        valid_client_pem = util.filter_valid_files_urls(
            [client_pem_path], self.tmp_path_prefix
        )
        if valid_client_pem is False:
            logger.error(
                f"[{self._state.hostname}:{self._state.port}] client_pem_path was provided but is not a valid URL or file does not exist"
            )
            return False
        if isinstance(valid_client_pem, list) and len(valid_client_pem) == 1:
            self._client_pem_path = valid_client_pem[0]
        logger.info(
            f"[{self._state.hostname}:{self._state.port}] Negotiating with the server to derive expected client certificate subjects"
        )
        ctx = SSL.Context(method=getattr(SSL, Transport._default_connect_method))
        ctx.load_verify_locations(cafile=where())
        ctx.verify_mode = SSL.VERIFY_NONE
        ctx.check_hostname = False
        conn = SSL.Connection(ctx, self.prepare_socket())
        conn.connect((self._state.hostname, self._state.port))
        if ssl.HAS_SNI:
            conn.set_tlsext_host_name(idna.encode(self._state.hostname))
        conn.setblocking(1)
        conn.set_connect_state()
        util.do_handshake(conn)
        self.expected_client_subjects = conn.get_client_ca_list()
        conn.close()
        if len(self.expected_client_subjects) > 0:
            logger.info(
                f"[{self._state.hostname}:{self._state.port}] Checking client certificate"
            )
            self.client_certificate = load_certificate(
                FILETYPE_PEM, Path(self._client_pem_path).read_bytes()
            )
            logger.debug(
                f"[{self._state.hostname}:{self._state.port}] issuer subject: {self.client_certificate.get_issuer().commonName}"
            )
            for check in self.expected_client_subjects:
                logger.debug(
                    f"[{self._state.hostname}:{self._state.port}] expected subject: {check.commonName}"
                )
                if self.client_certificate.get_issuer().commonName == check.commonName:
                    self.client_certificate_match = True
                    return True
        return False

    def do_request(
        self,
        conn: SSL.Connection,
        method: str = "HEAD",
        uri_path: str = "/",
        protocol: str = "HTTP/1.1",
        request_compression: bool = True,
    ):
        if method.upper() not in ["HEAD", "GET", "OPTIONS"]:
            raise AttributeError(f"method {method} not supported")
        if protocol.upper() not in ["HTTP/1.0", "HTTP/1.1"]:
            raise AttributeError(f"protocol {protocol} not supported")
        if not isinstance(uri_path, str):
            raise AttributeError("uri_path not supported")
        if not uri_path.startswith("/"):
            uri_path = f"/{uri_path}"

        request = [
            f"{method.upper()} {uri_path} {protocol}",
            f"Host: {self._state.hostname}",
            "Accept: */*",
            "Cache-Control: max-age=0",
            "Connection: close",
            "Content-Length: 0",
            "User-Agent: pypi.org/project/trivialscan",
        ]
        if request_compression is True:
            request.append("Accept-Encoding: compress, gzip")
        request = "\r\n".join(request) + "\r\n\r\n"
        logger.info(f"[{self._state.hostname}:{self._state.port}] Request:\n{request}")
        head = b""
        try:
            conn.sendall(request.encode())
            while not head.endswith(b"\r\n\r\n"):
                if Transport.is_connection_closed(conn):
                    break
                head += conn.recv(1)
        except ConnectionResetError:
            pass
        except SSL.ZeroReturnError:
            pass
        except SSL.SysCallError:
            pass
        if method.upper() in ["HEAD", "OPTIONS"] or protocol.upper() == "HTTP/2":
            return head.decode(), None
        body = b""
        try:
            while b"\r\n\r\n" not in body:
                if Transport.is_connection_closed(conn):
                    break
                data = conn.recv(Transport._data_recv_size)
                if len(data) == 0:
                    break
                body += data
        except ConnectionResetError:
            pass
        except SSL.ZeroReturnError:
            pass
        return head.decode(), body.decode()

    def _protocol_handler(
        self, conn: SSL.Connection, protocol: str = "HTTP/1.1"
    ) -> bool:
        proto_map = {
            "HTTP/1.0": "http1_",
            "HTTP/1.1": "http1_1_",
        }
        logger.debug(f"[{self._state.hostname}:{self._state.port}] protocol {protocol}")
        head, _ = self.do_request(conn, protocol=protocol)
        logger.info(
            f"[{self._state.hostname}:{self._state.port}] Response headers:\n{head}"
        )
        header = Transport.parse_header(head)
        prefix = proto_map[protocol]
        response_code = int(header["response_code"])
        setattr(self, f"{prefix}support", header["protocol"].startswith(protocol))
        setattr(self, f"{prefix}code", response_code)
        setattr(self, f"{prefix}status", header["response_status"])
        setattr(self, f"{prefix}response_proto", header["protocol"])
        setattr(self, f"{prefix}headers", header["headers"])
        if self.client_initiated_renegotiation is None:
            total_renegotiations = conn.total_renegotiations()
            proceed = conn.renegotiate()
            if proceed:
                try:
                    conn.setblocking(0)
                    util.do_handshake(conn)
                    self.client_initiated_renegotiation = (
                        conn.total_renegotiations() > total_renegotiations
                    )
                except SSL.ZeroReturnError:
                    pass
                except Exception as ex:
                    logger.warning(ex, exc_info=True)
            self.client_initiated_renegotiation = (
                self.client_initiated_renegotiation is True
            )
        return True

    def _get_ocsp_response(
        self, issuer: Certificate, uri: str, timeout: int = 3
    ) -> OCSPResponse:
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(
            self.server_certificate.to_cryptography(), issuer, SHA1()
        )
        ocsp_request = builder.build()
        try:
            response = post(
                uri,
                data=ocsp_request.public_bytes(Encoding.DER),
                headers={"Content-Type": "application/ocsp-request"},
                timeout=timeout,
            )
        except Exception as ex:
            logger.warning(ex, exc_info=True)
            return None
        if response.status_code != 200:
            logger.warning(
                f"[{self._state.hostname}:{self._state.port}] HTTP request returned {response.status_code}"
            )
            return None
        response = load_der_ocsp_response(response.content)
        if response.response_status != OCSPResponseStatus.SUCCESSFUL:
            return None
        if response.serial_number != ocsp_request.serial_number:
            logger.debug(
                f"[{self._state.hostname}:{self._state.port}] Response serial number does not match request"
            )
            return None
        return response

    def _ocsp_handler(self, conn: SSL.Connection, assertion: bytes, userdata) -> bool:
        if not isinstance(self.server_certificate, X509):
            self.server_certificate = conn.get_peer_certificate()
            for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                self._certificate_chain.append(cert)
        issuer = util.issuer_from_chain(
            self.server_certificate, self._certificate_chain
        )
        if not isinstance(issuer, X509):
            logger.warning(
                f"[{self._state.hostname}:{self._state.port}] Issuer certificate not found in chain"
            )
            return False
        self._state.revocation_ocsp_stapling = False
        self._state.revocation_ocsp_must_staple = False
        ext = None
        try:
            ext = self.server_certificate.to_cryptography().extensions.get_extension_for_class(
                extensions.TLSFeature
            )
        except Exception:
            pass
        if ext is not None:
            for feature in ext.value:
                if feature == extensions.TLSFeatureType.status_request:
                    logger.debug(
                        f"[{self._state.hostname}:{self._state.port}] Peer presented a must-staple cert"
                    )
                    self._state.revocation_ocsp_must_staple = True
                    break
        response = None
        if assertion == b"":
            if self._state.revocation_ocsp_must_staple is True:
                return False  # stapled response is expected and required
            ext = self.server_certificate.to_cryptography().extensions.get_extension_for_class(
                extensions.AuthorityInformationAccess
            )
            if ext is None:
                return True  # stapled response is expected though not required, not very good but still a valid assertion
            uris = [
                desc.access_location.value
                for desc in ext.value
                if desc.access_method == oid.AuthorityInformationAccessOID.OCSP
            ]
            if not uris:
                return True  # stapled response is expected though not required, without any responders it is still a valid assertion
            for uri in uris:
                logger.debug(
                    f"[{self._state.hostname}:{self._state.port}] Requesting OCSP from responder {uri}"
                )
                response = self._get_ocsp_response(issuer.to_cryptography(), uri)
                if response is None:
                    continue
        if response is None and assertion != b"":
            self._state.revocation_ocsp_stapling = True
            response = load_der_ocsp_response(assertion)
        if response is None:
            logger.warning(
                f"[{self._state.hostname}:{self._state.port}] OCSP response is not available"
            )
            return False
        if response.this_update > datetime.utcnow():
            logger.error(
                f"[{self._state.hostname}:{self._state.port}] OCSP thisUpdate is future dated"
            )
            return False
        logger.info(
            f"[{self._state.hostname}:{self._state.port}] OCSP response received"
        )
        if response.revocation_reason:
            self._state.revocation_ocsp_reason = response.revocation_reason.value
        if response.revocation_time:
            self._state.revocation_ocsp_time = response.revocation_time.value
        if response.response_status.value in constants.OCSP_RESP_STATUS:
            self._state.revocation_ocsp_response = constants.OCSP_RESP_STATUS[
                response.response_status.value
            ]
        if response.certificate_status.value in constants.OCSP_CERT_STATUS:
            self._state.revocation_ocsp_status = constants.OCSP_CERT_STATUS[
                response.certificate_status.value
            ]
        return (
            response.response_status == OCSPResponseStatus.SUCCESSFUL
            and response.certificate_status == OCSPCertStatus.GOOD
        )

    def prepare_socket(self, timeout: int = 1):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(timeout)
        return sock

    def prepare_context(
        self, method: str = None, verify_mode: str = None, check_hostname: bool = False
    ) -> SSL.Context:
        if not isinstance(check_hostname, bool):
            raise TypeError(f"check_hostname {type(check_hostname)}, bool supported")
        if method is not None and not isinstance(method, str):
            raise TypeError(f"method {type(method)}, str supported")
        if method is None:
            method = Transport._default_connect_method
        if isinstance(method, str) and not hasattr(SSL, method):
            raise AttributeError(
                "Only available SSL methods on your system are supported"
            )
        if verify_mode is not None and not isinstance(verify_mode, str):
            raise TypeError(f"verify_mode {type(verify_mode)}, str supported")
        if verify_mode is None:
            verify_mode = Transport._default_connect_verify_mode
        if isinstance(verify_mode, str) and not hasattr(SSL, verify_mode):
            raise AttributeError(
                "Only available SSL verify modes on your system are supported"
            )
        ctx = SSL.Context(method=getattr(SSL, method))
        ctx.load_verify_locations(cafile=where())
        for cafile in self._cafiles:
            ctx.load_verify_locations(cafile=cafile)
        if self._state.certificate_mtls_expected and isinstance(
            self._client_pem_path, str
        ):
            ctx.use_certificate_file(
                certfile=self._client_pem_path, filetype=FILETYPE_PEM
            )
        ctx.verify_mode = verify_mode
        ctx.check_hostname = check_hostname
        return ctx

    def prepare_connection(
        self,
        context: SSL.Context,
        sock: socket = None,
        use_sni: bool = True,
        protocol: int = None,
    ) -> SSL.Connection:
        ctx = (
            ssl.SSLContext() if protocol is None else ssl.SSLContext(protocol=protocol)
        )
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False
        if sock is None:
            sock = self.prepare_socket()
        conn = SSL.Connection(
            context,
            ctx.wrap_socket(
                sock,
                do_handshake_on_connect=False,
                server_hostname=self._state.hostname,
            ),
        )
        conn.connect((self._state.hostname, self._state.port))
        conn.set_connect_state()
        if all([ssl.HAS_SNI, use_sni]):
            conn.set_tlsext_host_name(idna.encode(self._state.hostname))
        conn.setblocking(1)
        return conn

    def _verifier(
        self,
        conn: SSL.Connection,
        server_cert: X509,
        errno: int,
        depth: int,
        preverify_ok: int,
    ):
        # preverify_ok indicates, whether the verification of the server certificate in question was passed (preverify_ok=1) or not (preverify_ok=0)
        # https://www.openssl.org/docs/man1.0.2/man1/verify.html
        if errno in exceptions.X509_MESSAGES.keys():
            self.verifier_errors.append((server_cert, errno))
        return True

    def connect(
        self, tls_version: int, use_sni: bool = False, protocol: str = None
    ) -> None:
        logger.info(
            f"[{self._state.hostname}:{self._state.port}] Trying {constants.OPENSSL_VERSION_LOOKUP[tls_version]}"
        )
        ctx = self.prepare_context()
        ctx.set_verify(
            getattr(SSL, Transport._default_connect_verify_mode), self._verifier
        )
        ctx.set_max_proto_version(tls_version)
        ctx.set_ocsp_client_callback(self._ocsp_handler)
        ctx.set_options(
            _util.lib.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
            | _util.lib.SSL_OP_LEGACY_SERVER_CONNECT
        )
        conn = SSL.Connection(context=ctx, socket=self.prepare_socket())
        conn.request_ocsp()
        if all([use_sni, ssl.HAS_SNI]):
            logger.info(f"[{self._state.hostname}:{self._state.port}] using SNI")
            conn.set_tlsext_host_name(idna.encode(self._state.hostname))
        try:
            conn.connect((self._state.hostname, self._state.port))
            conn.set_connect_state()
            conn.setblocking(1)
            util.do_handshake(conn)
            self._state.negotiated_cipher = conn.get_cipher_name()
            self._state.negotiated_cipher_bits = conn.get_cipher_bits()
            negotiated_protocol = conn.get_protocol_version_name()
            self._state.negotiated_protocol = f"{negotiated_protocol} ({hex(constants.PROTOCOL_VERSION[negotiated_protocol])})"
            self._state.offered_tls_versions.append(self._state.negotiated_protocol)
            self.session_cache_mode = constants.SESSION_CACHE_MODE[
                native_openssl.SSL_CTX_get_session_cache_mode(conn._context._context)
            ]
            self.session_tickets = (
                native_openssl.SSL_SESSION_has_ticket(conn.get_session()._session) == 1
            )
            self.session_ticket_hints = (
                native_openssl.SSL_SESSION_get_ticket_lifetime_hint(
                    conn.get_session()._session
                )
                > 0
            )
            self._state.peer_address, _ = conn.getpeername()
            self._state.offered_ciphers = conn.get_cipher_list()
            if not isinstance(self.server_certificate, X509):
                self.server_certificate = conn.get_peer_certificate()
                for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                    self._certificate_chain.append(cert)
                logger.debug(
                    f"[{self._state.hostname}:{self._state.port}] Peer cert chain length: {len(self._certificate_chain)}"
                )
            self._state.certificates = util.get_certificates(
                self.server_certificate, self._certificate_chain, self._state.hostname
            )
            if protocol is not None:
                logger.info(
                    f"[{self._state.hostname}:{self._state.port}] Trying protocol {protocol}"
                )
                self._protocol_handler(conn, protocol)
            conn.shutdown()
        except SSL.Error as err:
            if all(
                x not in str(err)
                for x in [
                    "no protocols available",
                    "alert protocol",
                    "shutdown while in init",
                    "sslv3 alert handshake failure",
                ]
            ):
                logger.warning(err, exc_info=True)
        except Exception as ex:
            logger.warning(ex, exc_info=True)
        finally:
            conn.close()

    @staticmethod
    def is_connection_closed(
        conn: SSL.Connection, counter: int = 0, max_retries: int = 5
    ) -> bool:
        try:
            data = conn.recv(1, MSG_PEEK)
            if len(data) == 0:
                return True
        except SSL.WantReadError:
            if counter >= max_retries:
                return True
            sleep(0.5)
            return Transport.is_connection_closed(conn, counter + 1)
        except BlockingIOError:
            return False
        except SSL.ZeroReturnError:
            return True
        except ConnectionResetError:
            return True
        except SSL.SysCallError:
            return True
        except Exception as ex:
            logger.exception(ex)
            return False
        return False

    @staticmethod
    def parse_header(head: str) -> dict:
        ret = {"headers": {}, "response_code": 0, "response_status": "", "protocol": ""}
        i = 0
        for line in head.splitlines():
            i += 1
            if len(line) == 0:
                continue
            if i == 1 and len(line.split(" ")) >= 2:
                ret["protocol"], ret["response_code"], *extra = line.split(" ")
                ret["response_status"] = " ".join(extra)
            else:
                header = line.split(":")[0].lower()
                value = ":".join(line.split(":")[1:]).strip()
                if header in ret["headers"]:
                    prev = ret["headers"][header].split(", ")
                    ret["headers"][header] = ", ".join([value] + prev)
                else:
                    ret["headers"][header] = value
        return ret

    def header_exists(self, name: str, includes_value: str = None) -> bool:
        if not isinstance(name, str):
            raise AttributeError(
                f"Invalid value for name, got {type(name)} expected str"
            )
        if includes_value is not None:
            if not isinstance(includes_value, str):
                raise AttributeError(
                    f"Invalid value for includes_value, got {type(includes_value)} expected str"
                )
            return (
                name in self._state.http_headers
                and includes_value in self._state.http_headers[name]
            )
        else:
            return name in self._state.http_headers
