import logging
import ssl
from base64 import urlsafe_b64encode
from datetime import datetime
from socket import socket, AF_INET, SOCK_STREAM, MSG_PEEK
from pathlib import Path
from cryptography.x509.ocsp import load_der_ocsp_response, OCSPResponseStatus, OCSPCertStatus
from OpenSSL import SSL
from OpenSSL.SSL import _lib as native_openssl
from OpenSSL.crypto import X509, FILETYPE_PEM, X509Name, load_certificate
from certifi import where
from retry.api import retry
from hyperframe.frame import Frame, SettingsFrame
from hyperframe.exceptions import InvalidFrameError
from rich.progress import Progress, TaskID
import validators
import idna
from . import util
from . import exceptions


__module__ = 'tlsverify.metadata'
logger = logging.getLogger(__name__)

class Transport:
    host :str
    port :int
    client_pem_path :str
    negotiated_protocol :str
    negotiated_cipher :str
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
        self.ocsp_revocation_reason = None
        self.ocsp_revocation_time = None
        self.ocsp_response_status = None
        self.ocsp_certificate_status = None
        self.depth = {}

    def pre_client_authentication_check(self, client_pem_path :str = None, updater :tuple[Progress, TaskID] = None) -> bool:
        if not isinstance(self.port, int):
            raise TypeError(f"provided an invalid type {type(self.port)} for port, expected int")
        if validators.domain(self.host) is not True:
            raise ValueError(f"provided an invalid domain {self.host}")
        if not isinstance(client_pem_path, str):
            raise TypeError(f"provided an invalid type {type(client_pem_path)} for client_pem_path, expected str")
        progress, task = (None, None)
        if isinstance(updater, tuple):
            progress, task = updater
        self.client_certificate_expected = True
        self.client_certificate_match = False
        valid_client_pem = util.filter_valid_files_urls([client_pem_path], self.tmp_path_prefix)
        if valid_client_pem is False:
            logger.error(f'client_pem_path was provided but is not a valid URL or file does not exist')
            return False
        if isinstance(valid_client_pem, list) and len(valid_client_pem) == 1:
            self.client_pem_path = valid_client_pem[0]
        logger.info('Negotiating with the server to derive expected client certificate subjects')
        ctx = SSL.Context(method=getattr(SSL, self.default_connect_method))
        ctx.load_verify_locations(cafile=where())
        ctx.verify_mode = SSL.VERIFY_NONE
        ctx.check_hostname = False
        conn = SSL.Connection(ctx, socket(AF_INET, SOCK_STREAM))
        conn.connect((self.host, self.port))
        conn.settimeout(3)
        if ssl.HAS_SNI:
            conn.set_tlsext_host_name(idna.encode(self.host))
        conn.setblocking(1)
        conn.set_connect_state()
        if isinstance(progress, Progress): progress.update(task, advance=1)
        try:
            conn.do_handshake()
            self.expected_client_subjects = conn.get_client_ca_list()
        except Exception as ex:
            logger.warning(ex, exc_info=True)
        finally:
            conn.close()
        if isinstance(progress, Progress): progress.update(task, advance=1)
        if len(self.expected_client_subjects) > 0:
            logger.info('Checking client certificate')
            self.client_certificate = load_certificate(FILETYPE_PEM, Path(self.client_pem_path).read_bytes())
            logger.debug(f'issuer subject: {self.client_certificate.get_issuer().commonName}')
            for check in self.expected_client_subjects:
                logger.debug(f'expected subject: {check.commonName}')
                if self.client_certificate.get_issuer().commonName == check.commonName:
                    self.client_certificate_match = True
                    if isinstance(progress, Progress): progress.update(task, advance=1)
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
            raise AttributeError(f'uri_path not supported')
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
                    conn.do_handshake()
                    self.client_renegotiation = conn.total_renegotiations() > total_renegotiations
                except SSL.ZeroReturnError: pass
                except Exception as ex:
                    logger.warning(ex, exc_info=True)
            self.client_renegotiation = self.client_renegotiation is True
        return True

    def _ocsp_handler(self, conn :SSL.Connection, assertion :bytes):
        ocsp = load_der_ocsp_response(assertion)
        self.ocsp_revocation_reason = ocsp.revocation_reason
        self.ocsp_revocation_time = ocsp.revocation_time
        self.ocsp_response_status = util.OCSP_RESP_STATUS[ocsp.response_status]
        self.ocsp_certificate_status = util.OCSP_CERT_STATUS[ocsp.certificate_status]
        return ocsp.response_status == OCSPResponseStatus.SUCCESSFUL and ocsp.certificate_status == OCSPCertStatus.GOOD

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

    def prepare_connection(self, context :SSL.Context) -> SSL.Connection:
        ctx = ssl.SSLContext()
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(1)
        conn = SSL.Connection(context, ctx.wrap_socket(sock, do_handshake_on_connect=False))
        conn.connect((self.host, self.port))
        conn.set_connect_state()
        if ssl.HAS_SNI is True:
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

    @retry((SSL.WantReadError), tries=20, delay=0.5, logger=logger)
    def _http2(self, conn :SSL.Connection, request :Frame, response_wait :int = 3) -> Frame:
        logger.info(f'HTTP/2 Request:\n{request}')
        try:
            conn.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            conn.sendall(request.serialize())
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
            except (SSL.ZeroReturnError, SSL.WantReadError):
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

    def test_h2c(self, method :str = 'GET', uri_path :str = '/', timeout :int = 3, include_settings :bool = True) -> Frame:
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
        sock.settimeout(timeout)
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
        logger.info(f'HTTP/2 clear text Response,\n{response.decode()}')
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
            raise AttributeError(f'uri_path not supported')
        if not uri_path.startswith('/'):
            uri_path = f'/{uri_path}'
        def _con():
            ctx = self.prepare_context()
            ctx.set_alpn_protos([b'h2', b'http/1.1'])
            # rfc7540 section 9.2
            ctx.set_options(ssl.OP_NO_COMPRESSION | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3)
            ctx.set_cipher_list(b"ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
            conn = self.prepare_connection(ctx)
            conn.settimeout(response_wait)
            try:
                conn.do_handshake()
            except Exception as ex:
                logger.warning(ex, exc_info=True)
            return conn

        request = Transport.decode_http2_frame(b'\x00\x00\x13\x00\x09\x00\x00\x00\x01\x0Ahello' + b'\0' * 10)
        resp = self._http2(_con(), request, response_wait)
        if isinstance(resp, Frame):
            self.http2_support = True
            self.http2_response_frame = str(resp)

    def connect(self, tls_version :int, use_sni :bool = False, protocol :str = None):
        logger.info(f'Trying TLS version {util.OPENSSL_VERSION_LOOKUP[tls_version]}')
        ctx = SSL.Context(method=getattr(SSL, Transport.default_connect_method))
        ctx.load_verify_locations(cafile=where())
        for cafile in self.cafiles:
            ctx.load_verify_locations(cafile=cafile)
        if self.client_pem_path is not None:
            ctx.use_certificate_file(certfile=self.client_pem_path, filetype=FILETYPE_PEM)
        ctx.set_verify(getattr(SSL, Transport.default_connect_verify_mode), self._verifier)
        ctx.set_ocsp_client_callback(self._ocsp_handler)
        ctx.set_max_proto_version(tls_version)
        ctx.check_hostname = False
        conn = SSL.Connection(ctx, socket(AF_INET, SOCK_STREAM))
        conn.settimeout(3)
        conn.setblocking(1)
        if all([use_sni, ssl.HAS_SNI]):
            logger.info('using SNI')
            conn.set_tlsext_host_name(idna.encode(self.host))        
        try:
            conn.connect((self.host, self.port))
            conn.do_handshake()
            conn.request_ocsp()
            self.session_cache_mode = util.SESSION_CACHE_MODE[native_openssl.SSL_CTX_get_session_cache_mode(conn._context._context)]
            self.session_tickets = native_openssl.SSL_SESSION_has_ticket(conn.get_session()._session) == 1
            self.session_ticket_hints = native_openssl.SSL_SESSION_get_ticket_lifetime_hint(conn.get_session()._session) > 0
            self.peer_address, _ = conn.getpeername()
            self.ciphers = conn.get_cipher_list()
            if not isinstance(self.server_certificate, X509):
                self.server_certificate = conn.get_peer_certificate()
                self.negotiated_cipher = conn.get_cipher_name()
                self.negotiated_protocol = conn.get_protocol_version_name()
                for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                    self.certificate_chain.append(cert)
                logger.debug(f'Peer cert chain length: {len(self.certificate_chain)}')
            if protocol is not None:
                logger.info(f'Trying protocol {protocol}')
                self._protocol_handler(conn, protocol)
            conn.shutdown()
        except SSL.Error as err:
            if not any(x in str(err) for x in ['no protocols available', 'alert protocol', 'shutdown while in init']):
                logger.warning(err, exc_info=True)
        except Exception as ex:
            logger.warning(ex, exc_info=True)
        finally:
            conn.close()

    def connect_least_secure(self, cafiles :list = None, use_sni :bool = False, updater :tuple[Progress, TaskID] = None) -> bool:
        if not isinstance(self.port, int):
            raise TypeError(f"provided an invalid type {type(self.port)} for port, expected int")
        if validators.domain(self.host) is not True:
            raise ValueError(f"provided an invalid domain {self.host}")
        progress, task = (None, None)
        if isinstance(updater, tuple):
            progress, task = updater
        if cafiles is not None:
            if not isinstance(cafiles, list):
                raise TypeError(f"provided an invalid type {type(cafiles)} for cafiles, expected list")
            valid_cafiles = util.filter_valid_files_urls(cafiles)
            if valid_cafiles is False:
                raise AttributeError(f'cafiles was provided but is not a valid URLs or files do not exist')
            if isinstance(valid_cafiles, list):
                self.cafiles = valid_cafiles
        for version in [SSL.SSL3_VERSION, SSL.TLS1_VERSION, SSL.TLS1_1_VERSION, SSL.TLS1_2_VERSION, SSL.TLS1_3_VERSION]:
            self.connect(tls_version=version, use_sni=use_sni)
            if isinstance(progress, Progress): progress.update(task, advance=1)
            if isinstance(self.server_certificate, X509):
                if all([use_sni, ssl.HAS_SNI]):
                    self.sni_support = True
                for protocol in ['HTTP/1.0', 'HTTP/1.1']:
                    self.connect(tls_version=version, use_sni=use_sni, protocol=protocol)
                self.test_h2c()
                self.test_http2()
                if isinstance(progress, Progress): progress.update(task, advance=1)
                return True
        return False

    @staticmethod
    def is_connection_closed(conn: SSL.Connection) -> bool:
        try:
            data = conn.recv(1, MSG_PEEK)
            if len(data) == 0:
                return True
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
