import logging
import ssl
from os import path
from datetime import timedelta
from time import sleep
from socket import socket, AF_INET, SOCK_STREAM, MSG_PEEK
from pathlib import Path
from cryptography.x509.ocsp import (
    OCSPResponse,
    load_der_ocsp_response,
    OCSPResponseStatus,
    OCSPRequestBuilder,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import SSL, _util
from OpenSSL.SSL import _lib as native_openssl
from OpenSSL.crypto import X509, FILETYPE_PEM, X509Name, load_certificate
from certifi import where
from requests_cache import CachedSession
import validators
import idna
from .. import exceptions, util, constants
from ..transport.state import TransportState
from ..certificate import ClientCertificate

__module__ = "trivialscan.transport"

SUPPORTED_OCSP_HASHES: list[hashes.HashAlgorithm] = [
    hashes.SHA1,
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
]
logger = logging.getLogger(__name__)


class Transport:
    _client_pem_path: str
    session_cache_mode: str
    server_certificate: X509
    _client_certificate: X509
    client_certificate: ClientCertificate
    client_certificate_match: bool
    client_certificate_trusted: bool
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
    _ocsp: dict
    revocation_ocsp_assertion: bytes

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
        self._ocsp = {}
        self._client_pem_path = None
        self._cafiles = []
        self._certificate_chain = []
        self.server_certificate = None
        self._state.certificate_mtls_expected = None
        self._client_certificate = None
        self.client_certificate_match = None
        self.client_certificate_trusted = None
        self.client_initiated_renegotiation = None
        self.certificates = []
        self.verifier_errors = []
        self.expected_client_subjects = []
        self.revocation_ocsp_assertion = b""
        self._session = CachedSession(
            path.join("/tmp", "trivialscan", hostname),
            backend="filesystem",
            use_temp=True,
            expire_after=timedelta(minutes=15),
        )

    @property
    def state(self) -> TransportState:
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
                f"{self._state.hostname}:{self._state.port} client_pem_path was provided but is not a valid URL or file does not exist"
            )
            return False
        if isinstance(valid_client_pem, list) and len(valid_client_pem) == 1:
            self._client_pem_path = valid_client_pem[0]
        logger.info(
            f"{self._state.hostname}:{self._state.port} Negotiating with the server to derive expected client certificate subjects"
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
        logger.info(
            f"{self._state.hostname}:{self._state.port} Checking client certificate"
        )
        self._client_certificate = load_certificate(
            FILETYPE_PEM, Path(self._client_pem_path).read_bytes()
        )
        self.client_certificate = ClientCertificate(self._client_certificate)
        self.client_certificate_trusted = any(
            [
                trust_store["is_trusted"]
                for trust_store in self.client_certificate.trust_stores
            ]
        )
        if len(self.expected_client_subjects) > 0:
            logger.debug(
                f"{self._state.hostname}:{self._state.port} issuer subject: {self._client_certificate.get_issuer().commonName}"
            )
            for check in self.expected_client_subjects:
                logger.debug(
                    f"{self._state.hostname}:{self._state.port} expected subject: {check.commonName}"
                )
                self.client_certificate_match = (
                    self._client_certificate.get_issuer().commonName == check.commonName
                )

        return self.client_certificate_match and self.client_certificate_trusted

    def get_ocsp_response(self, uri: str, timeout: int = 3) -> OCSPResponse:
        ocsp_response = None
        issuer = util.issuer_from_chain(
            self.server_certificate, self._certificate_chain
        )
        if not issuer:
            return None

        for _hash in SUPPORTED_OCSP_HASHES:
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(
                self.server_certificate.to_cryptography(),
                issuer.to_cryptography(),
                _hash(),
            )
            ocsp_request = builder.build()
            try:
                response = self._session.post(
                    uri,
                    data=ocsp_request.public_bytes(Encoding.DER),
                    headers={"Content-Type": "application/ocsp-request"},
                    timeout=timeout,
                )
                if response.status_code != 200:
                    logger.warning(
                        f"{self._state.hostname}:{self._state.port} HTTP request returned {response.status_code}"
                    )
                    continue
                ocsp_response = load_der_ocsp_response(response.content)
                if ocsp_response.serial_number == ocsp_request.serial_number:
                    break
                logger.debug(
                    f"{self._state.hostname}:{self._state.port} Response serial number does not match request"
                )

            except Exception as ex:
                logger.warning(ex, exc_info=True)

        if (
            ocsp_response
            and ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL
        ):
            return None
        return ocsp_response

    def _ocsp_handler(self, conn: SSL.Connection, assertion: bytes, userdata) -> bool:
        self.revocation_ocsp_assertion = assertion
        return True

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

    def connect(self, tls_version: int, use_sni: bool = False) -> None:
        logger.info(
            f"{self._state.hostname}:{self._state.port} Trying {constants.OPENSSL_VERSION_LOOKUP[tls_version]}"
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
            logger.info(f"{self._state.hostname}:{self._state.port} using SNI")
            conn.set_tlsext_host_name(idna.encode(self._state.hostname))
        try:
            conn.connect((self._state.hostname, self._state.port))
            conn.set_connect_state()
            conn.setblocking(1)
            util.do_handshake(conn)
            self._state.peer_address, _ = conn.getpeername()
            self._state.offered_ciphers = conn.get_cipher_list()
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
            self.expected_client_subjects = conn.get_client_ca_list()
            if not isinstance(self.server_certificate, X509):
                self.server_certificate = conn.get_peer_certificate()
                for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                    self._certificate_chain.append(cert)
                logger.debug(
                    f"{self._state.hostname}:{self._state.port} Peer cert chain length: {len(self._certificate_chain)}"
                )
            self._state.certificates = util.get_certificates(
                self.server_certificate, self._certificate_chain
            )
            conn.shutdown()
        except SSL.Error as err:
            if all(
                x not in str(err)
                for x in [
                    "no protocols available",
                    "alert protocol",
                    "shutdown while in init",
                    "sslv3 alert handshake failure",
                    "invalid status response",
                ]
            ):
                logger.warning(err, exc_info=True)
        except Exception as ex:
            logger.warning(ex, exc_info=True)
        finally:
            conn.close()

    def specify_tls_version(
        self,
        min_tls_version: int = None,
        max_tls_version: int = None,
        use_sni: bool = False,
        response_wait: int = 3,
    ) -> str:
        if min_tls_version is not None and not isinstance(min_tls_version, int):
            raise TypeError(f"min_tls_version {type(min_tls_version)}, int supported")
        if max_tls_version is not None and not isinstance(max_tls_version, int):
            raise TypeError(f"max_tls_version {type(max_tls_version)}, int supported")
        if not isinstance(response_wait, int):
            raise TypeError(f"response_wait {type(response_wait)}, int supported")
        protocol = None
        ctx = self.prepare_context()
        ctx.set_options(_util.lib.SSL_OP_TLS_ROLLBACK_BUG)
        try:
            if min_tls_version is not None:
                logger.info(
                    f"min protocol {constants.OPENSSL_VERSION_LOOKUP[min_tls_version]}"
                )
                ctx.set_min_proto_version(min_tls_version)
            if max_tls_version is not None:
                logger.info(
                    f"max protocol {constants.OPENSSL_VERSION_LOOKUP[max_tls_version]}"
                )
                ctx.set_max_proto_version(max_tls_version)
        except SSL.Error as ex:
            logger.warning(ex, exc_info=True)
            return protocol
        conn = self.prepare_connection(
            context=ctx,
            sock=self.prepare_socket(timeout=response_wait),
            use_sni=use_sni,
        )
        try:
            conn.settimeout(response_wait)
            util.do_handshake(conn)
            protocol = conn.get_protocol_version_name()
            logger.info(f"Negotiated {protocol}")
            conn.shutdown()
        except SSL.Error as err:
            if all(
                x not in str(err)
                for x in [
                    "no protocols available",
                    "alert protocol",
                    "shutdown while in init",
                    "sslv3 alert handshake failure",
                    "invalid status response",
                ]
            ):
                logger.warning(err, exc_info=True)
        finally:
            conn.close()
        return protocol

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
