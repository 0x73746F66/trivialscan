import json
import hashlib
import logging
from base64 import b64encode
from datetime import datetime
from pathlib import Path
import asn1crypto
from ssl import PEM_cert_to_DER_cert
from OpenSSL.crypto import X509, Error, X509Name, dump_privatekey, dump_certificate, load_certificate, FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT, TYPE_RSA, TYPE_DSA, TYPE_DH, TYPE_EC
from cryptography import x509
from cryptography.x509 import Certificate, extensions, PolicyInformation
from certvalidator.errors import PathValidationError, RevokedError, InvalidCertificateError, PathBuildingError
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.style import Style
from . import util
from . import exceptions
from .transport import Transport
from .metadata import Metadata
from tlsverify import metadata

__module__ = 'tlsverify.validator'
logger = logging.getLogger(__name__)

class Validator:
    _peer :bool
    _pem :bytes
    _der :bytes
    x509 :X509
    certificate :Certificate
    _pem_certificate_chain :list
    certificate_chain :list
    transport :Transport
    tmp_path_prefix = '/tmp'

    def __init__(self, peer :bool = False) -> None:
        self._peer = peer
        self.certificate_valid = False
        self.validation_checks = {}
        self.certificate_verify_messages = []
        self.certificate_chain_valid = None
        self.certificate_chain_validation_result = None
        self._pem = None
        self._der = None
        self.x509 = None
        self.certificate = None
        self._pem_certificate_chain = []
        self.certificate_chain = []

    def __repr__ (self) -> str:
        certificate_verify_messages = '", "'.join(self.certificate_verify_messages)
        validation_checks = json.dumps(self.validation_checks)
        res = f'<Validator(certificate_valid={self.certificate_valid}, '
        if self._peer is False:
            res += f'certificate_chain_valid={self.certificate_chain_valid}, '
            res += f'certificate_chain_validation_result={self.certificate_chain_validation_result}, '
        res += f'certificate_verify_messages=["{certificate_verify_messages}"]", ' +\
               f'validation_checks={validation_checks}, ' +\
               'metadata=<tlsverify.metadata.Metadata>, ' +\
               'transport=<tlsverify.transport.Transport>, ' +\
               'x509=<OpenSSL.crypto.X509>, ' +\
               '_pem=<bytes>, ' +\
               '_der=<bytes>, ' +\
               'certificate=<cryptography.x509.Certificate>)>'
        return res

    def to_rich(self) -> Table:
        def any_to_string(value, delimiter='\n') -> str:
            if isinstance(value, str):
                return value
            if value is None:
                return 'Unknown'
            if isinstance(value, bool):
                return 'True' if value else 'False'
            if isinstance(value, bytes):
                return value.decode()
            if isinstance(value, list) and isinstance(value[0], str):
                return delimiter.join(value)
            if isinstance(value, list) and not isinstance(value[0], str):
                n = []
                for d in value:
                    n.append(any_to_string(d, delimiter))
                return any_to_string(n)
            if isinstance(value, dict):
                return delimiter.join([f'{key}={str(value[key])}' for key in value.keys()])
            return str(value)
        fingerprints = ['certificate_sha256_fingerprint', 'certificate_sha1_fingerprint', 'certificate_md5_fingerprint', 'certificate_subject_key_identifier', 'certificate_authority_key_identifier']
        skip = ['host', 'port', 'offered_ciphers', 'certificate_subject', 'certificate_serial_number', 'certificate_san', 'certificate_extensions', 'subjectKeyIdentifier', 'authorityKeyIdentifier']
        title = str('Peer: ' if self._peer else 'TLS: ') + self.metadata.certificate_subject
        caption = '\n'.join([f'{self.metadata.host}:{self.metadata.port} ({self.metadata.peer_address})', self.metadata.certificate_serial_number])
        title_style = Style(bold=True, color='green' if self.certificate_valid else 'bright_red')
        table = Table(title=title, caption=caption, title_style=title_style)
        table.add_column("", justify="right", style="cyan", no_wrap=True)
        table.add_column("Result", justify="left")
        table.add_row('certificate_valid', any_to_string(self.certificate_valid))
        if self._peer:
            skip.extend(['certificate_client_authentication', 'client_certificate_expected', 'certificate_valid_tls_usage', 'certification_authority_authorization', 'dnssec', 'scsv_support', 'compression_support', 'peer_address', 'http_expect_ct_report_uri', 'http_xss_protection', 'http_status_code', 'http1_support', 'http1_1_support', 'http2_support'])
            skip.extend(['sni_support', 'negotiated_protocol', 'negotiated_cipher', 'weak_cipher', 'strong_cipher', 'forward_anonymity', 'session_resumption_caching', 'session_resumption_tickets', 'session_resumption_ticket_hint', 'client_renegotiation', 'http_hsts', 'http_xfo', 'http_csp', 'http_coep', 'http_coop', 'http_corp', 'http_nosniff', 'http_unsafe_referrer'])
        else:
            table.add_row('certificate_chain_valid', any_to_string(self.certificate_chain_valid))
            table.add_row('certificate_chain_validation_result', any_to_string(self.certificate_chain_validation_result))
        for i, err in enumerate(self.certificate_verify_messages):
            table.add_row(f'Note {i+1}', err)
        for key in self.validation_checks.keys():
            table.add_row(f'Rule {key}', any_to_string(self.validation_checks[key]))
        for key in list(vars(self.metadata).keys()):
            if key not in skip:
                table.add_row(key, util.str_n_split(getattr(self.metadata, key)).upper() if key in fingerprints and isinstance(getattr(self.metadata, key), str) else any_to_string(getattr(self.metadata, key)))
        for v in self.metadata.certificate_extensions:
            if v['name'] not in skip:
                table.add_row(v['name'], any_to_string(v, ' ') if v['name'] not in v else any_to_string(v[v['name']], ' '))
        return table

    def mount(self, transport :Transport):
        if not isinstance(transport, Transport):
            raise TypeError(f"provided an invalid type {type(transport)} for transport, expected an instance of <tlsverify.transport.Transport>")
        self.transport = transport
        self.extract_transport_metadata(transport)
        if isinstance(transport.server_certificate, X509):
            self.init_x509(transport.server_certificate)
        self.load_verifier_errors(transport.verifier_errors)

    def init_der(self, der :bytes):
        self._der = der
        logger.debug('added ASN1/DER bytes')
        self.x509 = load_certificate(FILETYPE_ASN1, der)
        logger.debug('added pyOpenSSL x509')
        self._pem = dump_certificate(FILETYPE_PEM, self.x509)
        logger.debug('added PEM bytes')
        self.certificate = self.x509.to_cryptography()
        logger.debug('added lib cryptography object')
        self.extract_x509_metadata(self.x509)

    def init_pem(self, pem :bytes):
        self._pem = pem
        logger.debug('added PEM bytes')
        self.x509 = load_certificate(FILETYPE_PEM, pem)
        logger.debug('added pyOpenSSL x509')
        self._der = PEM_cert_to_DER_cert(self._pem.decode())
        logger.debug('added ASN1/DER bytes')
        self.certificate = self.x509.to_cryptography()
        logger.debug('added lib cryptography object')
        self.extract_x509_metadata(self.x509)

    def init_x509(self, x509 :X509):
        self.x509 = x509
        logger.debug('added pyOpenSSL x509')
        self._pem = dump_certificate(FILETYPE_PEM, x509)
        logger.debug('added PEM bytes')
        self._der = PEM_cert_to_DER_cert(self._pem.decode())
        logger.debug('added ASN1/DER bytes')
        self.certificate = x509.to_cryptography()
        logger.debug('added lib cryptography object')
        self.extract_x509_metadata(self.x509)

    def cert_to_text(self) -> str:
        logger.debug('dump_certificate x509 FILETYPE_TEXT')
        return dump_certificate(FILETYPE_TEXT, self.x509).decode()

    def extract_transport_metadata(self, transport :Transport):
        if not hasattr(self, 'metadata') or not isinstance(self.metadata, Metadata):
            self.metadata = Metadata(
                host=transport.host,
                port=transport.port
            )
        self._pem_certificate_chain = util.convert_x509_to_PEM(transport.certificate_chain)
        self.certificate_chain = transport.certificate_chain
        self.metadata.peer_address = transport.peer_address
        # self.metadata.revocation_ocsp_stapling = 
        self.metadata.revocation_ocsp_status = transport.ocsp_certificate_status
        self.metadata.revocation_ocsp_response = transport.ocsp_response_status
        self.metadata.revocation_ocsp_reason = transport.ocsp_revocation_reason
        self.metadata.revocation_ocsp_time = transport.ocsp_revocation_time
        if self._peer:
            return
        self.metadata.offered_ciphers = transport.ciphers
        self.metadata.client_certificate_expected = transport.client_certificate_expected is True
        self.metadata.negotiated_cipher = transport.negotiated_cipher
        if any(self.metadata.negotiated_cipher.startswith(c) for c in ['DHE', 'ECDHE']):
            self.metadata.forward_anonymity = True
        if self.metadata.negotiated_cipher not in util.NOT_KNOWN_WEAK_CIPHERS:
            self.metadata.weak_cipher = True
        if self.metadata.negotiated_cipher in util.STRONG_CIPHERS:
            self.metadata.strong_cipher = True
        self.metadata.negotiated_protocol = transport.negotiated_protocol
        self.metadata.sni_support = transport.sni_support
        self.metadata.session_resumption_caching = transport.session_cache_mode in ['session_resumption_both', 'session_resumption_caching']
        self.metadata.session_resumption_tickets = transport.session_tickets
        self.metadata.session_resumption_ticket_hint = transport.session_ticket_hints
        self.metadata.compression_support = self.header_exists(name='content-encoding', includes_value='gzip')
        self.metadata.client_renegotiation = transport.client_renegotiation
        self.metadata.http_hsts = self.header_exists(name='strict-transport-security', includes_value='max-age')
        self.metadata.http_expect_ct_report_uri = self.header_exists(name='expect-ct', includes_value='report-uri')
        self.metadata.http_xfo = self.header_exists(name='x-frame-options') or self.header_exists(name='content-security-policy', includes_value='frame-ancestors')
        self.metadata.http_nosniff = self.header_exists(name='x-content-type-options', includes_value='nosniff')
        self.metadata.http_csp = self.header_exists(name='content-security-policy')
        self.metadata.http_coep = self.header_exists(name='cross-origin-embedder-policy', includes_value='require-corp')
        self.metadata.http_coop = self.header_exists(name='cross-origin-opener-policy', includes_value='same-origin')
        self.metadata.http_corp = self.header_exists(name='cross-origin-resource-policy', includes_value='same-origin')
        self.metadata.http_unsafe_referrer = self.header_exists(name='referrer-policy', includes_value='unsafe-url')
        self.metadata.http_xss_protection = self.header_exists(name='x-xss-protection', includes_value='1; mode=block')
        http_statuses = []
        if transport.http1_support:
            http_statuses.append(transport.http1_code)
        if transport.http1_1_support:
            http_statuses.append(transport.http1_1_code)
        self.metadata.http_status_code = min(*http_statuses, 511 if transport.client_certificate_expected else 505)
        self.metadata.http1_support = transport.http1_support
        self.metadata.http1_1_support = transport.http1_1_support
        self.metadata.http2_support = transport.http2_support

    def extract_x509_metadata(self, x509 :X509):
        if not hasattr(self, 'metadata') or not isinstance(self.metadata, Metadata):
            self.metadata = Metadata()

        self.metadata.certificate_extensions, _, _ = util.gather_key_usages(self.certificate)
        self.metadata.certificate_private_key_pem = None
        public_key = x509.get_pubkey()
        if public_key.type() == TYPE_RSA:
            self.metadata.certificate_public_key_type = 'RSA'
            self.metadata.certificate_private_key_pem = dump_privatekey(FILETYPE_PEM, public_key).decode()
        if public_key.type() == TYPE_DSA:
            self.metadata.certificate_public_key_type = 'DSA'
            self.metadata.certificate_private_key_pem = dump_privatekey(FILETYPE_PEM, public_key).decode()
        if public_key.type() == TYPE_DH:
            self.metadata.certificate_public_key_type = 'DH'
        if public_key.type() == TYPE_EC:
            self.metadata.certificate_public_key_type = 'EC'
        self.metadata.certificate_key_size = public_key.bits()
        self.metadata.certificate_serial_number_decimal = x509.get_serial_number()
        self.metadata.certificate_serial_number = util.convert_decimal_to_serial_bytes(x509.get_serial_number())
        self.metadata.certificate_serial_number_hex = '{0:#0{1}x}'.format(x509.get_serial_number(), 4)
        subject = x509.get_subject()
        self.metadata.certificate_subject = "".join("/{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())
        issuer: X509Name = x509.get_issuer()
        self.metadata.certificate_issuer = issuer.commonName
        self.metadata.certificate_issuer_country = issuer.countryName
        self.metadata.certificate_signature_algorithm = x509.get_signature_algorithm().decode('ascii')
        self.metadata.certificate_pin_sha256 = b64encode(hashlib.sha256(asn1crypto.x509.Certificate.load(self._der).public_key.dump()).digest()).decode()
        self.metadata.certificate_sha256_fingerprint = hashlib.sha256(self._der).hexdigest()
        self.metadata.certificate_sha1_fingerprint = hashlib.sha1(self._der).hexdigest()
        self.metadata.certificate_md5_fingerprint = hashlib.md5(self._der).hexdigest()
        self.metadata.certificate_san = util.get_san(self.certificate)
        self.metadata.certificate_valid_tls_usage = util.key_usage_exists(self.certificate, 'digital_signature') is True and util.key_usage_exists(self.certificate, 'serverAuth') is True
        not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), util.X509_DATE_FMT)
        not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), util.X509_DATE_FMT)
        self.metadata.certificate_not_before = not_before.isoformat()
        self.metadata.certificate_not_after = not_after.isoformat()
        self.metadata.certificate_common_name = util.extract_certificate_common_name(self.certificate)
        self.metadata.certificate_subject_key_identifier = None
        self.metadata.certificate_authority_key_identifier = None
        for ext in self.metadata.certificate_extensions:
            if ext['name'] == 'TLSFeature' and 'rfc6066' in ext['features']:
                self.metadata.revocation_ocsp_must_staple = True
            if ext['name'] == 'subjectKeyIdentifier':
                self.metadata.certificate_subject_key_identifier = ext[ext['name']]
            if ext['name'] == 'authorityKeyIdentifier':
                self.metadata.certificate_authority_key_identifier = ext[ext['name']]
        policies = []
        try:
            policies = self.certificate.extensions.get_extension_for_class(extensions.CertificatePolicies).value._policies
        except extensions.ExtensionNotFound:
            pass
        for policy in policies:
            if not isinstance(policy, PolicyInformation): continue
            if policy.policy_identifier._dotted_string in util.VALIDATION_OID.keys():
                self.metadata.certificate_validation_type = util.VALIDATION_OID[policy.policy_identifier._dotted_string]

    def header_exists(self, name :str, includes_value :str = None) -> bool:
        if not isinstance(name, str):
            raise AttributeError(f'Invalid value for name, got {type(name)} expected str')
        checks = []
        if includes_value is not None:
            if not isinstance(includes_value, str):
                raise AttributeError(f'Invalid value for includes_value, got {type(includes_value)} expected str')
            checks.append(self.transport.http1_support and name in self.transport.http1_headers and includes_value in self.transport.http1_headers[name])
            checks.append(self.transport.http1_1_support and name in self.transport.http1_1_headers and includes_value in self.transport.http1_1_headers[name])
        else:
            checks.append(self.transport.http1_support and name in self.transport.http1_headers)
            checks.append(self.transport.http1_1_support and name in self.transport.http1_1_headers)
        return any(checks)

    def client_authentication(self, client_pem :str, cafiles :list[str] = None) -> str:
        client_cert = None
        client_pem_err = AttributeError(f'client_pem was provided "{client_pem}" but is not a valid URL or file does not exist')
        if client_pem is None or not isinstance(client_pem, str):
            raise client_pem_err
        res = util.filter_valid_files_urls([client_pem], client_pem_err, self.tmp_path_prefix)
        if len(res) == 1:
            client_pem = res[0]
        expected_subjects = util.get_server_expected_client_subjects(host=self.metadata.host, port=self.metadata.port, cafiles=cafiles)
        if len(expected_subjects) > 0:
            logger.info('Checking client certificate')
            client_cert_path = Path(client_pem)
            cert = load_certificate(FILETYPE_PEM, client_cert_path.read_bytes())
            issuer_subject = cert.get_issuer()
            logger.debug(f'issuer subject: {issuer_subject.commonName}')
            for check in expected_subjects:
                logger.debug(f'expected subject: {check.commonName}')
                if issuer_subject.commonName == check.commonName:
                    client_cert = client_pem
                    break
        return client_cert

    def load_verifier_errors(self, errors :list[tuple[X509, int]]):
        if not isinstance(errors, list):
            return
        for cert, errno in errors:
            message = exceptions.X509_MESSAGES[errno]
            if errno in exceptions.X509_MESSAGES and self.x509.get_serial_number() == cert.get_serial_number() and message not in self.certificate_verify_messages:
                self.certificate_verify_messages.append(exceptions.X509_MESSAGES[errno])

    def verify(self, updater :tuple[Progress, TaskID] = None) -> bool:
        progress, task = (None, None)
        if isinstance(updater, tuple):
            progress, task = updater

        ca = util.get_basic_constraints(self.certificate)
        if self._peer is False:
            logger.debug('Server certificate validations')
            self.validation_checks['basic_constraints_ca'] = True
            if self.transport.client_certificate_expected:
                self.metadata.certificate_client_authentication = self.transport.client_certificate_match and isinstance(self.transport.client_certificate, X509) and self.transport.negotiated_protocol is not None and util.key_usage_exists(self.certificate, 'clientAuth') is True
                self.validation_checks['client_certificate_permits_authentication_usage'] = isinstance(self.transport.client_certificate, X509) and util.key_usage_exists(self.transport.client_certificate.to_cryptography(), 'clientAuth') is True
                self.validation_checks['client_authentication'] = self.metadata.certificate_client_authentication
                if self.validation_checks['client_authentication'] is False:
                    self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_CLIENT_AUTHENTICATION)
            if isinstance(ca, bool) and ca is True:
                self.validation_checks['basic_constraints_ca'] = False
                self.certificate_verify_messages.append('server certificates should not be a CA')
            self.validation_checks['certificate_valid_tls_usage'] = util.key_usage_exists(self.certificate, 'digital_signature') is True and util.key_usage_exists(self.certificate, 'serverAuth') is True
            self.validation_checks['common_name_valid'] = util.validate_common_name(self.metadata.certificate_common_name, self.metadata.host) is True
            self.validation_checks['match_hostname'] = util.match_hostname(self.metadata.host, self.certificate)
            self.metadata.certificate_is_self_signed = util.is_self_signed(self.certificate)
            self.validation_checks['not_self_signed'] = self.metadata.certificate_is_self_signed is False
            if self.metadata.certificate_is_self_signed:
                self.validation_checks['trusted_ca'] = False
                self.certificate_verify_messages.append('The CA is not properly imported as a trusted CA into the browser, Chrome based browsers will block visitors and show them ERR_CERT_AUTHORITY_INVALID')
            self.validation_checks['avoid_deprecated_protocols'] = self.metadata.negotiated_protocol not in util.WEAK_PROTOCOL.keys()
            if self.validation_checks['avoid_deprecated_protocols'] is False:
                self.certificate_verify_messages.append(util.WEAK_PROTOCOL[self.metadata.negotiated_protocol])
            # if self.metadata.revocation_ocsp_stapling is True:
            #     self.validation_checks['ocsp_staple_satisfied'] = False
            #     if self.metadata.revocation_ocsp_response is not None:
            #         self.validation_checks['ocsp_staple_satisfied'] = True
            if self.metadata.revocation_ocsp_must_staple is True:
                self.validation_checks['ocsp_must_staple_satisfied'] = False
                if self.metadata.revocation_ocsp_status == util.OCSP_CERT_STATUS[0]:
                    self.validation_checks['ocsp_must_staple_satisfied'] = True
            if isinstance(progress, Progress): progress.update(task, advance=1)

        logger.debug('Common certificate validations')
        not_after = datetime.fromisoformat(self.metadata.certificate_not_after)
        not_before = datetime.fromisoformat(self.metadata.certificate_not_before)
        self.validation_checks['not_expired'] = not_after > datetime.utcnow()
        if self.validation_checks['not_expired'] is False:
            self.certificate_verify_messages.append(f'Expired {(datetime.utcnow() - not_after).days} days ago' if not_after < datetime.utcnow() else f'Valid for {(not_after - datetime.utcnow()).days} days')
        self.validation_checks['issued_past_tense'] = not_before < datetime.utcnow()
        if self.validation_checks['issued_past_tense'] is False:
            self.certificate_verify_messages.append(f'Will only be valid for use in {(datetime.utcnow() - self.metadata.certificate_not_before).days} days')
        self.validation_checks['common_name_defined'] = self.metadata.certificate_common_name is not None
        self.validation_checks['avoid_known_weak_signature_algorithm'] = self.metadata.certificate_signature_algorithm not in util.KNOWN_WEAK_SIGNATURE_ALGORITHMS.keys()
        if self.validation_checks['avoid_known_weak_signature_algorithm'] is False:
            self.certificate_verify_messages.append(util.KNOWN_WEAK_SIGNATURE_ALGORITHMS[self.metadata.certificate_signature_algorithm])
        self.validation_checks['avoid_known_weak_keys'] = self.metadata.certificate_public_key_type not in util.KNOWN_WEAK_KEYS.keys() or self.metadata.certificate_key_size > util.WEAK_KEY_SIZE[self.metadata.certificate_public_key_type]
        if self.validation_checks['avoid_known_weak_keys'] is False:
            self.certificate_verify_messages.append(util.KNOWN_WEAK_KEYS[self.metadata.certificate_public_key_type])
        
        if self._peer:
            path_lengths = [x for x in [list(util.get_basic_constraints(cert.to_cryptography()))[1] for cert in self.certificate_chain] if isinstance(x, int)]
            if len(path_lengths) == 1:
                paths = -1
                for cert in self.certificate_chain:
                    ca, _ = util.get_basic_constraints(cert.to_cryptography())
                    if ca is True: paths += 1
                for cert in self.certificate_chain:
                    if cert.get_serial_number() == self.x509.get_serial_number():
                        ca, path_length = util.get_basic_constraints(cert.to_cryptography())
                        if ca is True and path_lengths[0] == path_length:
                            self.metadata.certificate_root_ca = True
                        elif ca is True:
                            self.metadata.certificate_intermediate_ca = True

        self.certificate_valid = all(list(self.validation_checks.values()))
        if isinstance(progress, Progress): progress.update(task, advance=1)
        return self.certificate_valid

    def verify_chain(self) -> bool:
        if self._pem_certificate_chain is None or (isinstance(self._pem_certificate_chain, list) and len(self._pem_certificate_chain) == 0):
            return False
        self.metadata.certificate_extensions, validator_key_usage, validator_extended_key_usage = util.gather_key_usages(self.certificate)
        validation_result = f'Validated: {",".join(validator_key_usage + validator_extended_key_usage)}'
        self.validation_checks['not_revoked'] = True
        try:
            logger.debug('certificate chain validation')
            util.validate_certificate_chain(self._der, self._pem_certificate_chain, validator_key_usage, validator_extended_key_usage)
        except RevokedError as ex:
            logger.debug(ex, stack_info=True)
            self.validation_checks['not_revoked'] = False
            self.certificate_chain_valid = False
            validation_result = str(ex)
        except InvalidCertificateError as ex:
            logger.debug(ex, stack_info=True)
            self.certificate_chain_valid = False
            validation_result = str(ex)
        except PathValidationError as ex:
            logger.debug(ex, stack_info=True)
            self.certificate_chain_valid = False
            validation_result = str(ex)
        except PathBuildingError as ex:
            logger.debug(ex, stack_info=True)
            self.certificate_chain_valid = False
            validation_result = str(ex)
        except Exception as ex:
            logger.warning(ex, stack_info=True)
            validation_result = str(ex)

        basic_constraints_path_length = True
        path_lengths = [x for x in [list(util.get_basic_constraints(cert.to_cryptography()))[1] for cert in self.certificate_chain] if isinstance(x, int)]
        if len(path_lengths) > 1:
            self.certificate_verify_messages.append(f'Too many TLS extension basicConstraints path_length present, got {len(path_lengths)}')
        elif len(path_lengths) == 1:
            paths = -1
            for cert in self.certificate_chain:
                ca, _ = util.get_basic_constraints(cert.to_cryptography())
                if ca is True: paths += 1
            if paths > path_lengths[0]:
                basic_constraints_path_length = False
                validation_result = f'TLS extension basicConstraints path_length violation. {paths} additional intermediate CA, expected {path_lengths[0]}'

        self.validation_checks['basic_constraints_path_length'] = basic_constraints_path_length
        if basic_constraints_path_length is False:
            self.certificate_chain_valid = False

        self.certificate_chain_validation_result = validation_result
        self.certificate_chain_valid = self.certificate_chain_valid is not False
        self.certificate_valid = all(list(self.validation_checks.values()))
        return self.certificate_valid and self.certificate_chain_valid

    @staticmethod
    def str_n_split(**kwargs):
        logger.warning(DeprecationWarning('Validator.str_n_split is now a util.str_n_split and will soon be removed.'), stack_info=True)
        return util.str_n_split(**kwargs)

    @staticmethod
    def convert_x509_to_PEM(**kwargs) -> list[bytes]:
        logger.warning(DeprecationWarning('Validator.convert_x509_to_PEM is now a util.convert_x509_to_PEM and will soon be removed.'), stack_info=True)
        return util.convert_x509_to_PEM(**kwargs)
