import logging
import ssl
from base64 import urlsafe_b64encode
from datetime import datetime
from time import sleep
from socket import socket, AF_INET, SOCK_STREAM, MSG_PEEK
from pathlib import Path
from cryptography.x509 import extensions, oid
from cryptography.x509.base import Certificate
from cryptography.x509.ocsp import OCSPResponse, load_der_ocsp_response, OCSPResponseStatus, OCSPCertStatus, OCSPRequestBuilder
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import SSL, _util
from OpenSSL.SSL import _lib as native_openssl
from OpenSSL.crypto import X509, FILETYPE_PEM, X509Name, load_certificate
from certifi import where
from hyperframe.frame import Frame, SettingsFrame
from hyperframe.exceptions import InvalidFrameError
from requests import post
import validators
import idna
from . import exceptions, util, constants


__module__ = 'tlsverify.metadata'
logger = logging.getLogger(__name__)

FAKE_PROTOCOLS = ['TLSv1.4', 'TLSv1.8', 'TLSv2', 'TLSv2.1', 'TLSv2.3']

class Transport:
    host :str
    port :int
    client_pem_path :str
    negotiated_protocol :str
    negotiated_cipher :str
    negotiated_cipher_bits :int
    peer_address :str
    sni_support :bool
    http2_support :bool
    http2_cleartext_support :bool
    http2_response_frame :str
    http1_support :bool
    http1_code :int
    http1_status :str
    http1_response_proto :str
    http1_headers :dict
    http1_1_support :bool
    http1_1_code :int
    http1_1_status :str
    http1_1_response_proto :str
    http1_1_headers :dict
    ocsp_stapling : bool
    ocsp_must_staple : bool
    ocsp_revocation_reason :str
    ocsp_revocation_time :str
    ocsp_response_status :str
    ocsp_certificate_status :str
    ciphers :list
    compression :str
    client_renegotiation :bool
    session_cache_mode :str
    session_tickets :bool
    session_ticket_hints :bool
    server_certificate :X509
    client_certificate :X509
    client_certificate_expected :bool
    client_certificate_match :bool
    tls_downgrade :bool
    offered_tls_versions :list
    tls_version_intolerance :bool
    tls_version_intolerance_versions :list
    tls_version_interference :bool
    tls_version_interference_versions :list
    long_handshake_intolerance :bool
    preferred_protocol :str
    cafiles :list
    certificate_chain :list[X509]
    verifier_errors :list[tuple[X509], int]
    expected_client_subjects :list[X509Name]
    tmp_path_prefix :str = '/tmp'
    default_connect_method :str = 'SSLv23_METHOD'
    default_connect_verify_mode :str = 'VERIFY_NONE'
    data_recv_size :int = 8096
    depth :dict

    def __init__(self, host :str, port :int = 443) -> None:
        if not isinstance(port, int):
            raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
        self.port = port
        if validators.domain(host) is not True:
            raise ValueError(f"provided an invalid domain {host}")
        self.host = host
        self.client_pem_path = None
        self.client_pem_path = None
        self.negotiated_protocol = None
        self.negotiated_cipher = None
        self.negotiated_cipher_bits = None
        self.ciphers = []
        self.client_renegotiation = None
        self.compression = None
        self.session_cache_mode = None
        self.session_tickets = None
        self.session_ticket_hints = None
        self.server_certificate = None
        self.client_certificate = None
        self.client_certificate_expected = None
        self.client_certificate_match = None
        self.certificate_chain = []
        self.verifier_errors = []
        self.cafiles = []
        self.expected_client_subjects = []
        self.sni_support = False
        self.http1_support = False
        self.http1_1_support = False
        self.http2_support = False
        self.http2_cleartext_support = False
        self.peer_address = None
        self.tls_downgrade = None
        self.offered_tls_versions = []
        self.tls_version_interference = None
        self.tls_version_interference_versions = []
        self.tls_version_intolerance = None
        self.tls_version_intolerance_versions = []
        self.long_handshake_intolerance = None
        self.preferred_protocol = None
        self.ocsp_stapling = None
        self.ocsp_must_staple = None
        self.ocsp_revocation_reason = None
        self.ocsp_revocation_time = None
        self.ocsp_response_status = None
        self.ocsp_certificate_status = None
        self.depth = {}

    def pre_client_authentication_check(self, client_pem_path :str = None, progress_bar :callable = lambda *args: None) -> bool:
        if not isinstance(self.port, int):
            raise TypeError(f"provided an invalid type {type(self.port)} for port, expected int")
        if validators.domain(self.host) is not True:
            raise ValueError(f"provided an invalid domain {self.host}")
        if not isinstance(client_pem_path, str):
            raise TypeError(f"provided an invalid type {type(client_pem_path)} for client_pem_path, expected str")

        self.client_certificate_expected = True
        self.client_certificate_match = False
        valid_client_pem = util.filter_valid_files_urls([client_pem_path], self.tmp_path_prefix)
        if valid_client_pem is False:
            logger.error('client_pem_path was provided but is not a valid URL or file does not exist')
            return False
        if isinstance(valid_client_pem, list) and len(valid_client_pem) == 1:
            self.client_pem_path = valid_client_pem[0]
        logger.info('Negotiating with the server to derive expected client certificate subjects')
        ctx = SSL.Context(method=getattr(SSL, self.default_connect_method))
        ctx.load_verify_locations(cafile=where())
        ctx.verify_mode = SSL.VERIFY_NONE
        ctx.check_hostname = False
        conn = SSL.Connection(ctx, self.prepare_socket())
        conn.connect((self.host, self.port))
        if ssl.HAS_SNI:
            conn.set_tlsext_host_name(idna.encode(self.host))
        conn.setblocking(1)
        conn.set_connect_state()
        progress_bar()
        util.do_handshake(conn)
        self.expected_client_subjects = conn.get_client_ca_list()
        conn.close()
        progress_bar()
        if len(self.expected_client_subjects) > 0:
            logger.info('Checking client certificate')
            self.client_certificate = load_certificate(FILETYPE_PEM, Path(self.client_pem_path).read_bytes())
            logger.debug(f'issuer subject: {self.client_certificate.get_issuer().commonName}')
            for check in self.expected_client_subjects:
                logger.debug(f'expected subject: {check.commonName}')
                if self.client_certificate.get_issuer().commonName == check.commonName:
                    self.client_certificate_match = True
                    progress_bar()
                    return True
        return False

    def _verifier(self, conn :SSL.Connection, server_cert :X509, errno :int, depth :int, preverify_ok :int):
        # preverify_ok indicates, whether the verification of the server certificate in question was passed (preverify_ok=1) or not (preverify_ok=0)
        # https://www.openssl.org/docs/man1.0.2/man1/verify.html
        if errno in exceptions.X509_MESSAGES.keys():
            self.verifier_errors.append((server_cert, errno))
        return True

    def do_request(self, conn :SSL.Connection, method :str = 'HEAD', uri_path :str = '/', protocol :str = 'HTTP/1.1', request_compression :bool = True):
        if method.upper() not in ['HEAD', 'GET', 'OPTIONS']:
            raise AttributeError(f'method {method} not supported')
        if protocol.upper() not in ['HTTP/1.0', 'HTTP/1.1']:
            raise AttributeError(f'protocol {protocol} not supported')
        if not isinstance(uri_path, str):
            raise AttributeError('uri_path not supported')
        if not uri_path.startswith('/'):
            uri_path = f'/{uri_path}'

        request = [
            f"{method.upper()} {uri_path} {protocol}",
            f"Host: {self.host}",
            "Accept: */*",
            "Cache-Control: max-age=0",
            "Connection: close",
            "Content-Length: 0",
            "User-Agent: pypi.org/project/tls-verify/",
        ]
        if request_compression is True:
            request.append("Accept-Encoding: compress, gzip")
        request = "\r\n".join(request) + "\r\n\r\n"
        logger.info(f'Request:\n{request}')
        conn.sendall(request.encode())
        head = b""
        try:
            while not head.endswith(b"\r\n\r\n"):
                if Transport.is_connection_closed(conn): break
                head += conn.recv(1)
        except ConnectionResetError:
            pass
        except SSL.ZeroReturnError:
            pass
        if method.upper() in ['HEAD', 'OPTIONS'] or protocol.upper() == 'HTTP/2':
            return head.decode(), None
        body = b""
        try:
            while b"\r\n\r\n" not in body:
                if Transport.is_connection_closed(conn): break
                data = conn.recv(Transport.data_recv_size)
                if len(data) == 0: break
                body += data
        except ConnectionResetError:
            pass
        except SSL.ZeroReturnError:
            pass
        return head.decode(), body.decode()

    def _protocol_handler(self, conn :SSL.Connection, protocol :str ='HTTP/1.1'):
        proto_map = {
            'HTTP/1.0': 'http1_',
            'HTTP/1.1': 'http1_1_',
        }
        logger.debug(f'protocol {protocol}')
        head, _ = self.do_request(conn, protocol=protocol)
        logger.info(f'Response headers:\n{head}')
        header = Transport.parse_header(head)
        prefix = proto_map[protocol]
        response_code = int(header['response_code'])
        setattr(self, f'{prefix}support', header['protocol'].startswith(protocol))
        setattr(self, f'{prefix}code', response_code)
        setattr(self, f'{prefix}status', header['response_status'])
        setattr(self, f'{prefix}response_proto', header['protocol'])
        setattr(self, f'{prefix}headers', header['headers'])
        if self.client_renegotiation is None:
            total_renegotiations = conn.total_renegotiations()
            proceed = conn.renegotiate()
            if proceed:
                try:
                    conn.setblocking(0)
                    util.do_handshake(conn)
                    self.client_renegotiation = conn.total_renegotiations() > total_renegotiations
                except SSL.ZeroReturnError: pass
                except Exception as ex:
                    logger.warning(ex, exc_info=True)
            self.client_renegotiation = self.client_renegotiation is True
        return True

    def _get_ocsp_response(self, issuer :Certificate, uri :str, timeout :int = 3) -> OCSPResponse:
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(self.server_certificate.to_cryptography(), issuer, SHA1())
        ocsp_request = builder.build()
        try:
            response = post(
                uri,
                data=ocsp_request.public_bytes(Encoding.DER),
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=timeout)
        except Exception as ex:
            logger.warning(ex, exc_info=True)
            return None
        if response.status_code != 200:
            logger.warning("HTTP request returned %d", response.status_code)
            return None
        response = load_der_ocsp_response(response.content)
        if response.response_status != OCSPResponseStatus.SUCCESSFUL:
            return None
        if response.serial_number != ocsp_request.serial_number:
            logger.debug("Response serial number does not match request")
            return None
        return response

    def _ocsp_handler(self, conn :SSL.Connection, assertion :bytes, userdata) -> bool:
        if not isinstance(self.server_certificate, X509):
            self.server_certificate = conn.get_peer_certificate()
            for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                self.certificate_chain.append(cert)
        issuer = util.issuer_from_chain(self.server_certificate, self.certificate_chain)
        if not isinstance(issuer, X509):
            logger.warning('Issuer certificate not found in chain')
            return False
        self.ocsp_stapling = False
        self.ocsp_must_staple = False
        ext = None
        try:
            ext = self.server_certificate.to_cryptography().extensions.get_extension_for_class(extensions.TLSFeature)
        except Exception:
            pass
        if ext is not None:
            for feature in ext.value:
                if feature == extensions.TLSFeatureType.status_request:
                    logger.debug("Peer presented a must-staple cert")
                    self.ocsp_must_staple = True
                    break
        response = None
        if assertion == b'':
            if self.ocsp_must_staple is True:
                return False # stapled response is expected and required
            ext = self.server_certificate.to_cryptography().extensions.get_extension_for_class(extensions.AuthorityInformationAccess)
            if ext is None:
                return True # stapled response is expected though not required, not very good but still a valid assertion
            uris = [desc.access_location.value for desc in ext.value if desc.access_method == oid.AuthorityInformationAccessOID.OCSP]
            if not uris:
                return True # stapled response is expected though not required, without any responders it is still a valid assertion
            for uri in uris:
                logger.debug(f"Requesting OCSP from responder {uri}")
                response = self._get_ocsp_response(issuer.to_cryptography(), uri)
                if response is None:
                    continue
        if response is None and assertion != b'':
            self.ocsp_stapling = True
            response = load_der_ocsp_response(assertion)
        if response is None:
            logger.warning("OCSP response is not available")
            return False
        if response.this_update > datetime.utcnow():
            logger.error("OCSP thisUpdate is future dated")
            return False
        logger.info("OCSP response received")
        if response.revocation_reason:
            self.ocsp_revocation_reason = response.revocation_reason.value
        if response.revocation_time:
            self.ocsp_revocation_time = response.revocation_time.value
        if response.response_status.value in constants.OCSP_RESP_STATUS:
            self.ocsp_response_status = constants.OCSP_RESP_STATUS[response.response_status.value]
        if response.certificate_status.value in constants.OCSP_CERT_STATUS:
            self.ocsp_certificate_status = constants.OCSP_CERT_STATUS[response.certificate_status.value]
        return response.response_status == OCSPResponseStatus.SUCCESSFUL and response.certificate_status == OCSPCertStatus.GOOD

    def prepare_socket(self, timeout :int = 1):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(timeout)
        return sock

    def prepare_context(self, method :str = None, verify_mode :str = None, check_hostname :bool = False) -> SSL.Context:
        if not isinstance(check_hostname, bool):
            raise TypeError(f'check_hostname {type(check_hostname)}, bool supported')
        if method is not None and not isinstance(method, str):
            raise TypeError(f'method {type(method)}, str supported')
        if method is None:
            method = Transport.default_connect_method
        if isinstance(method, str) and not hasattr(SSL, method):
            raise AttributeError('Only available SSL methods on your system are supported')
        if verify_mode is not None and not isinstance(verify_mode, str):
            raise TypeError(f'verify_mode {type(verify_mode)}, str supported')
        if verify_mode is None:
            verify_mode = Transport.default_connect_verify_mode
        if isinstance(verify_mode, str) and not hasattr(SSL, verify_mode):
            raise AttributeError('Only available SSL verify modes on your system are supported')
        ctx = SSL.Context(method=getattr(SSL, method))
        ctx.load_verify_locations(cafile=where())
        for cafile in self.cafiles:
            ctx.load_verify_locations(cafile=cafile)
        if self.client_certificate_expected and isinstance(self.client_pem_path, str):
            ctx.use_certificate_file(certfile=self.client_pem_path, filetype=FILETYPE_PEM)
        ctx.verify_mode = verify_mode
        ctx.check_hostname = check_hostname
        return ctx

    def prepare_connection(self, context :SSL.Context, sock :socket = None, use_sni :bool = True, protocol :int = None) -> SSL.Connection:
        ctx = ssl.SSLContext() if protocol is None else ssl.SSLContext(protocol=protocol)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False
        if sock is None:
            sock = self.prepare_socket()
        conn = SSL.Connection(context, ctx.wrap_socket(sock, do_handshake_on_connect=False, server_hostname=self.host))
        conn.connect((self.host, self.port))
        conn.set_connect_state()
        if all([ssl.HAS_SNI, use_sni]):
            conn.set_tlsext_host_name(idna.encode(self.host))
        conn.setblocking(1)
        return conn

    @staticmethod
    def decode_http2_frame(frame_data) -> Frame:
        try:
            f, length = Frame.parse_frame_header(frame_data[:9])
            f.parse_body(memoryview(frame_data[9:9 + length]))
        except InvalidFrameError:
            f = None
        return f

    def _http2(self, conn :SSL.Connection, request :Frame, response_wait :int = 3) -> Frame:
        logger.info(f'HTTP/2 Request:\n{request}')
        try:
            conn.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            conn.sendall(request.serialize())
        except SSL.WantReadError:
            sleep(0.5)
            return self._http2(conn, request, response_wait)
        except SSL.Error as err:
            if 'protocol is shutdown' not in str(err):
                logger.warning(err, exc_info=True)
        except SSL.ZeroReturnError:
            pass
        resp = None
        start = datetime.utcnow()
        frame_data = b''
        while True:
            try:
                if Transport.is_connection_closed(conn) or (datetime.utcnow()-start).seconds >= response_wait: break
                data = conn.recv(1024)
                if not data: break
                frame_data += data
            except (SSL.ZeroReturnError):
                break
            except Exception as ex:
                logger.warning(ex, exc_info=True)
                break
        try:
            resp = Transport.decode_http2_frame(frame_data)
            logger.info(f'Response data:\n{resp}')
            conn.shutdown()
        except Exception as ex:
            logger.warning(ex, exc_info=True)
        finally:
            conn.close()
        return resp

    def test_h2c(self, method :str = 'GET', uri_path :str = '/', response_wait :int = 3, include_settings :bool = True) -> Frame:
        logger.info(f'Testing HTTP/2 clear text')
        def _read(s :socket):
            resp = b''
            while not resp.endswith(b"\r\n\r\n"):
                try:
                    data = s.recv(1)
                except Exception:
                    break
                if not data: break
                resp += data
            return resp

        preamble = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        req_parts = [
            f"{method} {uri_path} HTTP/1.1",
            f"Host: {self.host}",
            "Accept: */*",
            "Connection: Upgrade",
        ]
        if include_settings:
            settings_frame = SettingsFrame(0, settings={
                SettingsFrame.HEADER_TABLE_SIZE: 4096,
                SettingsFrame.INITIAL_WINDOW_SIZE: 2 ** 16 - 1,
                SettingsFrame.MAX_FRAME_SIZE: 2 ** 14,
            })
            http2_settings = urlsafe_b64encode(settings_frame.serialize_body()).rstrip(b'=')
            req_parts.append(f"HTTP2-Settings: {http2_settings.decode()}")
            req_parts.append("Upgrade: h2c, HTTP2-Settings")
        else:
            req_parts.append("Upgrade: h2c")
        request = '\r\n'.join(req_parts) + '\r\n\r\n'
        self.http2_cleartext_support = False
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(response_wait)
        try:
            sock.connect((self.host, 80 if self.port == 443 else self.port))            
            sock.sendall(preamble)
            logger.info(f'HTTP/2 clear text Request,\n{request}')
            sock.sendall(request.encode())
            if include_settings:
                logger.info(f'HTTP2-Settings: {Transport.decode_http2_frame(settings_frame.serialize())}')
                sock.sendall(settings_frame.serialize())
        except Exception as ex:
            logger.warning(ex, exc_info=True)
        
        response = _read(sock)
        try:
            logger.info(f'HTTP/2 clear text Response,\n{response.decode("utf8")}')
        except UnicodeDecodeError:
            logger.info(f'HTTP/2 clear text Response,\n{response.decode("ISO-8859-1")}')
        if b'\r\n\r\n' in response:
            headers, _ = response.split(b'\r\n\r\n', 1)
            split_headers = headers.split()
            if split_headers[1] == b'101':
                self.http2_cleartext_support = True
        sock.close()

    def test_http2(self, uri_path :str = '/', response_wait :int = 3):
        if not any([ssl.HAS_ALPN, ssl.HAS_NPN]):
            return
        if not isinstance(response_wait, int):
            raise TypeError(f'response_wait {type(response_wait)}, int supported')
        if not isinstance(uri_path, str):
            raise AttributeError('uri_path not supported')
        if not uri_path.startswith('/'):
            uri_path = f'/{uri_path}'
        ctx = self.prepare_context()
        ctx.set_alpn_protos([b'h2', b'http/1.1'])
        # rfc7540 section 9.2
        ctx.set_options(ssl.OP_NO_COMPRESSION | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3)
        ctx.set_cipher_list(b"ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
        conn = self.prepare_connection(context=ctx, sock=self.prepare_socket(response_wait))
        conn.settimeout(response_wait)
        util.do_handshake(conn)
        request = Transport.decode_http2_frame(b'\x00\x00\x13\x00\x09\x00\x00\x00\x01\x0Ahello' + b'\0' * 10)
        resp = self._http2(conn, request, response_wait)
        if isinstance(resp, Frame):
            self.http2_support = True
            self.http2_response_frame = str(resp)

    def test_highest_tls_version(self, version, response_wait :int = 3):
        logger.warning(DeprecationWarning('Transport.test_highest_tls_version() was deprecated in version 0.4.4 and will be removed in version 0.5.0'), exc_info=True)
        self.test_tls_version(min_tls_version=version, response_wait=response_wait)

    def test_tls_version(self, min_tls_version :int = None, max_tls_version :int = None, use_sni :bool = False, response_wait :int = 3) -> str:
        if min_tls_version is not None and not isinstance(min_tls_version, int):
            raise TypeError(f'min_tls_version {type(min_tls_version)}, int supported')
        if max_tls_version is not None and not isinstance(max_tls_version, int):
            raise TypeError(f'max_tls_version {type(max_tls_version)}, int supported')
        if not isinstance(response_wait, int):
            raise TypeError(f'response_wait {type(response_wait)}, int supported')
        protocol = None
        ctx = self.prepare_context()
        ctx.set_options(_util.lib.SSL_OP_TLS_ROLLBACK_BUG)
        if min_tls_version is not None:
            logger.info(f'min protocol {constants.OPENSSL_VERSION_LOOKUP[min_tls_version]}')
            ctx.set_min_proto_version(min_tls_version)
        if max_tls_version is not None:
            logger.info(f'max protocol {constants.OPENSSL_VERSION_LOOKUP[max_tls_version]}')
            ctx.set_max_proto_version(max_tls_version)
        conn = self.prepare_connection(context=ctx, sock=self.prepare_socket(timeout=response_wait), use_sni=use_sni)
        conn.settimeout(response_wait)
        util.do_handshake(conn)
        protocol = conn.get_protocol_version_name()
        logger.info(f'Negotiated {protocol}')
        conn.shutdown()
        conn.close()
        return protocol

    def connect(self, tls_version :int, use_sni :bool = False, protocol :str = None):
        logger.info(f'Trying TLS version {constants.OPENSSL_VERSION_LOOKUP[tls_version]}')
        ctx = self.prepare_context()
        ctx.set_verify(getattr(SSL, Transport.default_connect_verify_mode), self._verifier)
        ctx.set_max_proto_version(tls_version)
        ctx.set_ocsp_client_callback(self._ocsp_handler)
        ctx.set_options(_util.lib.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | _util.lib.SSL_OP_LEGACY_SERVER_CONNECT)
        conn = SSL.Connection(context=ctx, socket=self.prepare_socket())
        conn.request_ocsp()
        if all([use_sni, ssl.HAS_SNI]):
            logger.info('using SNI')
            conn.set_tlsext_host_name(idna.encode(self.host))
        try:
            conn.connect((self.host, self.port))
            conn.set_connect_state()
            conn.setblocking(1)
            util.do_handshake(conn)
            self.negotiated_cipher = conn.get_cipher_name()
            self.negotiated_cipher_bits = conn.get_cipher_bits()
            negotiated_protocol = conn.get_protocol_version_name()
            self.negotiated_protocol = f'{negotiated_protocol} ({hex(constants.PROTOCOL_VERSION[negotiated_protocol])})'
            self.offered_tls_versions.append(self.negotiated_protocol)
            self.session_cache_mode = constants.SESSION_CACHE_MODE[native_openssl.SSL_CTX_get_session_cache_mode(conn._context._context)]
            self.session_tickets = native_openssl.SSL_SESSION_has_ticket(conn.get_session()._session) == 1
            self.session_ticket_hints = native_openssl.SSL_SESSION_get_ticket_lifetime_hint(conn.get_session()._session) > 0
            self.peer_address, _ = conn.getpeername()
            self.ciphers = conn.get_cipher_list()
            if not isinstance(self.server_certificate, X509):
                self.server_certificate = conn.get_peer_certificate()
                for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                    self.certificate_chain.append(cert)
                logger.debug(f'Peer cert chain length: {len(self.certificate_chain)}')
            if protocol is not None:
                logger.info(f'Trying protocol {protocol}')
                self._protocol_handler(conn, protocol)
            conn.shutdown()
        except SSL.Error as err:
            if all(
                x not in str(err)
                for x in [
                    'no protocols available',
                    'alert protocol',
                    'shutdown while in init',
                ]
            ):
                logger.warning(err, exc_info=True)
        except Exception as ex:
            logger.warning(ex, exc_info=True)
        finally:
            conn.close()

    def test_scsv(self, tls_version :int, use_sni :bool = True):
        """
        A connection of higher protocol indicates we have previously connected using the client fallback mechanism
        When a handshake is rejected (False) assume downgrade attacks were prevented
        """
        logger.info('Trying to derive SCSV')
        try:
            negotiated = self.test_tls_version(min_tls_version=tls_version, use_sni=use_sni)
            if negotiated:    
                self.preferred_protocol = f'{negotiated} ({hex(constants.PROTOCOL_VERSION[negotiated])})'
            else:
                self.preferred_protocol = self.negotiated_protocol
            self.offered_tls_versions.append(self.preferred_protocol)
            self.tls_downgrade = negotiated is not None
        except Exception:
            self.tls_downgrade = False

    def test_tls_all_versions(self, use_sni :bool = True):
        logger.info('Testing all TLS versions')
        for ver_name, tls_version in constants.PROTOCOL_VERSION.items():
            ver_display_name = f'{ver_name} ({hex(tls_version)})'
            if ver_name in FAKE_PROTOCOLS or ver_display_name in self.offered_tls_versions:
                continue
            try:
                negotiated = self.test_tls_version(max_tls_version=tls_version, use_sni=use_sni)
                supported = negotiated == ver_name
            except Exception:
                supported = False
            if supported is True:
                self.offered_tls_versions.append(ver_display_name)

    def test_tls_long_handshake_intolerance(self, version :int = None) -> bool:
        """
        If the Client Hello messages longer than 255 bytes and the connection fails
        Using ALL_CIPHERS is 3458 bytes so our Client Hello will be sufficiently long
        """
        native_ssl_openssl_version_map = {
            769: ssl.PROTOCOL_TLSv1,
            770: ssl.PROTOCOL_TLSv1_1,
            771: ssl.PROTOCOL_TLSv1_2,
            772: ssl.PROTOCOL_TLSv1_2,
        }
        protocol = native_ssl_openssl_version_map[version]
        ctx = ssl.SSLContext(protocol)
        sock = socket(AF_INET, SOCK_STREAM)
        context = SSL.Context(method=getattr(SSL, self.default_connect_method))
        if version == SSL.TLS1_3_VERSION:
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_1
            ctx.options |= ssl.OP_NO_TLSv1_2
            ctx.options |= ssl.OP_NO_COMPRESSION
            context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2 | SSL.OP_NO_COMPRESSION)
        if version == SSL.TLS1_2_VERSION:
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_1
            ctx.options |= ssl.OP_NO_TLSv1_3
            ctx.options |= ssl.OP_NO_COMPRESSION
            context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_3 | SSL.OP_NO_COMPRESSION)
        if version == SSL.TLS1_1_VERSION:
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_2
            ctx.options |= ssl.OP_NO_TLSv1_3
            ctx.options |= ssl.OP_NO_COMPRESSION
            context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_2 | SSL.OP_NO_TLSv1_3 | SSL.OP_NO_COMPRESSION)
        if version == SSL.TLS1_VERSION:
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3
            ctx.options |= ssl.OP_NO_TLSv1_1
            ctx.options |= ssl.OP_NO_TLSv1_2
            ctx.options |= ssl.OP_NO_TLSv1_3
            ctx.options |= ssl.OP_NO_COMPRESSION
            context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2 | SSL.OP_NO_TLSv1_3 | SSL.OP_NO_COMPRESSION)

        sock.settimeout(1)
        ctx.verify_mode = ssl.CERT_REQUIRED
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=where())
        for cafile in self.cafiles:
            context.load_verify_locations(cafile=cafile)
        if self.client_certificate_expected and isinstance(self.client_pem_path, str):
            context.use_certificate_file(certfile=self.client_pem_path, filetype=FILETYPE_PEM)
        ctx.set_ciphers(constants.ALL_CIPHERS)
        context.set_cipher_list(constants.ALL_CIPHERS.encode())
        context.set_min_proto_version(version)
        context.set_max_proto_version(version)
        conn = SSL.Connection(context, ctx.wrap_socket(sock, do_handshake_on_connect=False, server_hostname=self.host))
        negotiated_cipher = None
        try:
            conn.connect((self.host, self.port))
            conn.set_connect_state()
            if ssl.HAS_SNI:
                conn.set_tlsext_host_name(idna.encode(self.host))
            conn.setblocking(1)
            util.do_handshake(conn)
            negotiated_cipher = conn.get_cipher_name()
            conn.shutdown()
        except Exception as ex:
            logger.debug(ex, exc_info=True)
        finally:
            conn.close()
        return negotiated_cipher is None

    def test_tls_version_interference(self):
        """
        A rejected connection (typically the oldest or latest version, currently 1.3)
        when no mutual accepted TLS version can be negotiates is known as tls interference
        """
        for check_interference in ['TLSv1.3 (0x304)', 'TLSv1.2 (0x303)', 'TLSv1.1 (0x302)', 'TLSv1 (0x301)', 'SSLv3 (0x300)', 'SSLv2 (0x2ff)']:
            if check_interference not in self.offered_tls_versions:
                self.tls_version_interference_versions.append(check_interference)
        self.tls_version_interference = len(self.tls_version_interference_versions) > 0

    def test_tls_version_intolerance(self, use_sni :bool = True):
        """
        Protocol not understood by the server, the server should negotiate the highest protocol it knows
        A rejected connection indicates TLS version intolerance, and is not rfc5246 or rfc8446 compliant
        """
        logger.info('Trying to derive TLS version intolerance')
        for fake_proto in FAKE_PROTOCOLS:
            fake_ver = constants.PROTOCOL_VERSION[fake_proto]
            try:
                intolerance = self.test_tls_version(min_tls_version=fake_ver, use_sni=use_sni) is None
                if intolerance:
                    self.tls_version_intolerance_versions.append(f'{fake_proto} ({hex(fake_ver)})')
            except Exception:
                self.tls_version_intolerance_versions.append(f'{fake_proto} ({hex(fake_ver)})')
        self.tls_version_intolerance = len(self.tls_version_intolerance_versions) > 0

    def connect_least_secure(self, cafiles :list = None, use_sni :bool = False, progress_bar :callable = lambda *args: None) -> bool:
        if not isinstance(self.port, int):
            raise TypeError(f"provided an invalid type {type(self.port)} for port, expected int")
        if validators.domain(self.host) is not True:
            raise ValueError(f"provided an invalid domain {self.host}")
        if cafiles is not None:
            if not isinstance(cafiles, list):
                raise TypeError(f"provided an invalid type {type(cafiles)} for cafiles, expected list")
            valid_cafiles = util.filter_valid_files_urls(cafiles)
            if valid_cafiles is False:
                raise AttributeError('cafiles was provided but is not a valid URLs or files do not exist')
            if isinstance(valid_cafiles, list): self.cafiles = valid_cafiles

        tls_versions = [SSL.SSL3_VERSION, SSL.TLS1_VERSION, SSL.TLS1_1_VERSION, SSL.TLS1_2_VERSION, SSL.TLS1_3_VERSION]
        for index, version in enumerate(tls_versions):
            self.connect(tls_version=version, use_sni=use_sni) # Skip HTTP testing until negotiated
            progress_bar()
            if not isinstance(self.server_certificate, X509):
                continue
            progress_bar(5)

            if all([use_sni, ssl.HAS_SNI]):
                self.sni_support = True
            for protocol in ['HTTP/1.0', 'HTTP/1.1']:
                self.connect(tls_version=version, use_sni=use_sni, protocol=protocol)
                progress_bar()

            self.test_h2c(response_wait=3)
            progress_bar()

            self.test_http2(response_wait=3)
            progress_bar()

            self.long_handshake_intolerance = self.test_tls_long_handshake_intolerance(version)
            progress_bar()

            if version == SSL.TLS1_3_VERSION:
                # Already the highest TLS protocol, no downgrade possible
                self.tls_downgrade = False
                # server can only prefer this too
                self.preferred_protocol = constants.OPENSSL_VERSION_LOOKUP[version]
                self.test_tls_version_interference()
                progress_bar(12)
                self.test_tls_version_intolerance(use_sni) # sourcery skip: extract-duplicate-method
                progress_bar()
                return True

            self.test_scsv(tls_versions[index+1], use_sni)
            progress_bar()
            
            self.test_tls_all_versions(use_sni)
            progress_bar()

            self.test_tls_version_interference()
            progress_bar()

            self.test_tls_version_intolerance(use_sni)
            progress_bar()

            return True

        return False

    @staticmethod
    def is_connection_closed(conn: SSL.Connection, counter :int = 0, max_retries :int = 5) -> bool:
        try:
            data = conn.recv(1, MSG_PEEK)
            if len(data) == 0:
                return True
        except SSL.WantReadError:
            if counter >= max_retries: return True
            sleep(0.5)
            return Transport.is_connection_closed(conn, counter+1)
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
    def parse_header(head :str) -> dict:
        ret = {'headers': {}, 'response_code': 0, 'response_status': '', 'protocol': ''}
        i = 0
        for line in head.splitlines():
            i += 1
            if len(line) == 0:
                continue
            if i == 1 and len(line.split(' ')) >= 2:
                ret['protocol'], ret['response_code'], *extra = line.split(' ')
                ret['response_status'] = ' '.join(extra)
            else:
                header = line.split(':')[0].lower()
                value = ':'.join(line.split(':')[1:]).strip()
                if header in ret['headers']:
                    prev = ret['headers'][header].split(', ')
                    ret['headers'][header] = ', '.join([value] + prev)
                else:
                    ret['headers'][header] = value
        return ret
