import hashlib
import logging
from base64 import b64encode
from datetime import datetime
from pathlib import Path
import validators
import asn1crypto
from ssl import PEM_cert_to_DER_cert
from OpenSSL.crypto import X509, X509Name, dump_certificate, load_certificate, FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT, TYPE_RSA, TYPE_DSA, TYPE_DH, TYPE_EC
from cryptography.x509 import Certificate
from certvalidator.errors import PathValidationError, RevokedError, InvalidCertificateError, PathBuildingError
from validators.utils import ValidationFailure
from tlsverify import util
from tlsverify.exceptions import ValidationError
from tabulate import tabulate

__module__ = 'tlsverify'

logger = logging.getLogger(__name__)

class Validator:
    _pem :bytes
    _der :bytes
    x509 :X509
    certificate :Certificate
    _pem_certificate_chain :list
    certificate_chain :list
    metadata :util.Metadata

    def __init__(self, host :str = None, port :int = 443) -> None:
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
        self.metadata = None
        if host is not None:
            self.x509, self.certificate_chain, valid_subjects, protocol, cipher = util.get_certificates(host, port) #TODO handle clientAuth
            logger.debug('added pyOpenSSL x509')
            self.metadata = util.Metadata(host=host, port=port, negotiated_cipher=cipher, negotiated_protocol=protocol)
            if self.x509 is None or not self.certificate_chain:
                raise ValidationError(f'Unable to negotiate a TLS socket connection with server at {host}:{port} to obtain the Certificate')
            self._pem = dump_certificate(FILETYPE_PEM, self.x509)
            logger.debug('added PEM bytes')
            self._der = PEM_cert_to_DER_cert(self._pem.decode())
            logger.debug('added ASN1/DER bytes')
            self.certificate = self.x509.to_cryptography()
            logger.debug('added lib cryptography object')
            self._pem_certificate_chain = Validator.convert_x509_to_PEM(self.certificate_chain)

    def cert_to_text(self) -> str:
        logger.debug('dump_certificate x509 FILETYPE_TEXT')
        return dump_certificate(FILETYPE_TEXT, self.x509).decode()

    def tabulate(self) -> str:
        def any_to_string(value, delimiter='\n') -> str:
            if isinstance(value, str):
                return value
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
        skip = ['certificate_san', 'certificate_extensions', 'subjectKeyIdentifier', 'authorityKeyIdentifier']
        kv = [
            ['certificate_valid', self.certificate_valid],
            ['certificate_chain_valid', self.certificate_chain_valid],
            ['certificate_chain_validation_result', self.certificate_chain_validation_result]
        ]
        kv += [['Error', err] for err in self.certificate_verify_messages]
        kv += [[f'Check {key}', self.validation_checks[key]] for key in self.validation_checks.keys()]
        kv += [[key, getattr(self.metadata, key)] for key in list(vars(self.metadata).keys()) if key not in skip]
        kv += [[v['name'], any_to_string(v, ' ') if v['name'] not in v else any_to_string(v[v['name']], ' ')] for v in self.metadata.certificate_extensions if v['name'] not in skip]
        return tabulate(kv, tablefmt='tsv', disable_numparse=True, colalign=("right",))

    def init_der(self, der :bytes):
        self._der = der
        logger.debug('added ASN1/DER bytes')
        self.x509 = load_certificate(FILETYPE_ASN1, der)
        logger.debug('added pyOpenSSL x509')
        self._pem = dump_certificate(FILETYPE_PEM, self.x509)
        logger.debug('added PEM bytes')
        self.certificate = self.x509.to_cryptography()
        logger.debug('added lib cryptography object')

    def init_pem(self, pem :bytes):
        self._pem = pem
        logger.debug('added PEM bytes')
        self.x509 = load_certificate(FILETYPE_PEM, pem)
        logger.debug('added pyOpenSSL x509')
        self._der = PEM_cert_to_DER_cert(self._pem.decode())
        logger.debug('added ASN1/DER bytes')
        self.certificate = self.x509.to_cryptography()
        logger.debug('added lib cryptography object')

    def init_x509(self, x509 :X509):
        self.x509 = x509
        logger.debug('added pyOpenSSL x509')
        self._pem = dump_certificate(FILETYPE_PEM, x509)
        logger.debug('added PEM bytes')
        self._der = PEM_cert_to_DER_cert(self._pem.decode())
        logger.debug('added ASN1/DER bytes')
        self.certificate = x509.to_cryptography()
        logger.debug('added lib cryptography object')

    @staticmethod
    def convert_decimal_to_serial_bytes(decimal :int):
        # add leading 0
        a = "0%x" % decimal
        # force even num bytes, remove leading 0 if necessary
        b = a[1:] if len(a)%2==1 else a
        return format(':'.join(s.encode('utf8').hex().lower() for s in b))

    @staticmethod
    def str_n_split(input :str, n :int = 2, delimiter :str = ' '):
        return delimiter.join([input[i:i+n] for i in range(0, len(input), n)])

    @staticmethod
    def convert_x509_to_PEM(certificate_chain :list) -> list[bytes]:
        pem_certs = []
        for cert in certificate_chain:
            if not isinstance(cert, X509):
                raise ValidationError(f'convert_x509_to_PEM expected OpenSSL.crypto.X509, got {type(cert)}')
            pem_certs.append(dump_certificate(FILETYPE_PEM, cert))
        return pem_certs

    def extract_metadata(self):
        if not hasattr(self, 'metadata') or self.metadata is None:
            self.metadata = util.Metadata(host=None)
        public_key = self.x509.get_pubkey()
        if public_key.type() == TYPE_RSA:
            self.metadata.certificate_public_key_type = 'RSA'
        if public_key.type() == TYPE_DSA:
            self.metadata.certificate_public_key_type = 'DSA'
        if public_key.type() == TYPE_DH:
            self.metadata.certificate_public_key_type = 'DH'
        if public_key.type() == TYPE_EC:
            self.metadata.certificate_public_key_type = 'EC'
        self.metadata.certificate_key_size = public_key.bits()
        self.metadata.certificate_serial_number_decimal = self.x509.get_serial_number()
        self.metadata.certificate_serial_number = Validator.convert_decimal_to_serial_bytes(self.x509.get_serial_number())
        self.metadata.certificate_serial_number_hex = '{0:#0{1}x}'.format(self.x509.get_serial_number(), 4)
        subject = self.x509.get_subject()
        self.metadata.certificate_subject = "".join("/{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())
        issuer: X509Name = self.x509.get_issuer()
        self.metadata.certificate_issuer = issuer.commonName
        self.metadata.certificate_issuer_country = issuer.countryName
        self.metadata.certificate_signature_algorithm = self.x509.get_signature_algorithm().decode('ascii')
        self.metadata.certificate_pin_sha256 = b64encode(hashlib.sha256(asn1crypto.x509.Certificate.load(self._der).public_key.dump()).digest()).decode()
        self.metadata.certificate_sha256_fingerprint = hashlib.sha256(self._der).hexdigest()
        self.metadata.certificate_sha1_fingerprint = hashlib.sha1(self._der).hexdigest()
        self.metadata.certificate_md5_fingerprint = hashlib.md5(self._der).hexdigest()
        self.metadata.certificate_san = util.get_san(self.certificate)
        self.metadata.certificate_valid_tls_usage = util.key_usage_exists(self.certificate, 'digital_signature') is True and util.key_usage_exists(self.certificate, 'serverAuth') is True
        not_before = datetime.strptime(self.x509.get_notBefore().decode('ascii'), util.X509_DATE_FMT)
        not_after = datetime.strptime(self.x509.get_notAfter().decode('ascii'), util.X509_DATE_FMT)
        self.metadata.certificate_not_before = not_before.isoformat()
        self.metadata.certificate_not_after = not_after.isoformat()
        self.metadata.certificate_common_name = util.extract_certificate_common_name(self.certificate)
        for ext in self.metadata.certificate_extensions:
            if ext['name'] == 'TLSFeature' and 'rfc6066' in ext['features']:
                self.metadata.revocation_ocsp_stapling = True
                self.metadata.revocation_ocsp_must_staple = True
            if ext['name'] == 'subjectKeyIdentifier':
                self.metadata.certificate_subject_key_identifier = ext[ext['name']]
            if ext['name'] == 'authorityKeyIdentifier':
                self.metadata.certificate_authority_key_identifier = ext[ext['name']]

    def client_authentication(self, valid_subjects :list[tuple], client_pem :list[str], client_ca :str = None, cafiles :list[str] = None) -> bool:
        """
        valid_subjects: [[(b'C', b'US'),(b'ST', b'California'),(b'L', b'San Francisco'),(b'O', b'BadSSL'),(b'CN', b'BadSSL Client Root Certificate Authority')]]
        """
        raise NotImplementedError()

    def verify(self, host :str = None, port :int = None, peer :bool = False) -> bool:
        if not hasattr(self, 'metadata') or self.metadata is None:
            self.metadata = util.Metadata(host=host, port=port)
        if peer is False:
            logger.debug('Server certificate validations')
            if isinstance(host, str):
                self.metadata.host = host
            if validators.domain(self.metadata.host) is not True:
                raise ValueError(f"provided an invalid domain {host}")
            if isinstance(port, int):
                self.metadata.port = port
            self.validation_checks['certificate_valid_tls_usage'] = util.key_usage_exists(self.certificate, 'digital_signature') is True and util.key_usage_exists(self.certificate, 'serverAuth') is True
            self.validation_checks['common_name_valid'] = util.validate_common_name(self.metadata.certificate_common_name, self.metadata.host) is True
            self.validation_checks['match_hostname'] = util.match_hostname(self.metadata.host, self.certificate)
            self.metadata.certificate_is_self_signed = util.is_self_signed(self.certificate)
            self.validation_checks['not_self_signed'] = self.metadata.certificate_is_self_signed is False
            if self.metadata.certificate_is_self_signed:
                self.validation_checks['trusted_ca'] = False
                self.certificate_verify_messages.append('The CA is not properly imported as a trusted CA into the browser, Chrome based browsers will block visitors and show them ERR_CERT_AUTHORITY_INVALID')
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
        self.validation_checks['avoid_deprecated_protocols'] = self.metadata.negotiated_protocol not in util.WEAK_PROTOCOL.keys()
        if self.validation_checks['avoid_deprecated_protocols'] is False:
            self.certificate_verify_messages.append(util.WEAK_PROTOCOL[self.metadata.negotiated_protocol])
        self.certificate_valid = all(list(self.validation_checks.values()))
        return self.certificate_valid

    def verify_chain(self, certificate_chain :list[bytes] = None) -> bool:
        if certificate_chain is not None:
            self._pem_certificate_chain = certificate_chain
        self.metadata.certificate_extensions, validator_key_usage, validator_extended_key_usage = util.gather_key_usages(self.certificate)
        self.validation_checks['not_revoked'] = True
        try:
            logger.debug('certificate chain validation')
            util.validate_certificate_chain(self._der, self._pem_certificate_chain, validator_key_usage, validator_extended_key_usage)
        except RevokedError as ex:
            logger.debug(ex, exc_info=True)
            self.validation_checks['not_revoked'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except InvalidCertificateError as ex:
            logger.debug(ex, exc_info=True)
            self.validation_checks['certificate_chain_valid'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except PathValidationError as ex:
            logger.debug(ex, exc_info=True)
            self.validation_checks['certificate_chain_valid'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except PathBuildingError as ex:
            logger.debug(ex, exc_info=True)
            self.validation_checks['certificate_chain_valid'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except Exception as ex:
            logger.warning(ex, exc_info=True)
            self.validation_checks['certificate_chain_valid'] = False
            self.certificate_chain_validation_result = str(ex)

        if self.certificate_chain_validation_result is None:
            self.certificate_chain_valid = True
            self.certificate_chain_validation_result = f'Validated: {",".join(validator_key_usage + validator_extended_key_usage)}'

        self.certificate_valid = all(list(self.validation_checks.values()))
        self.extract_metadata()
        return self.certificate_valid and self.certificate_chain_valid

def verify(host :str, port :int = 443, cafiles :list = None, tlsext :bool = False, client_pem :str = None, client_ca :str = None) -> tuple[bool,list[Validator]]:
    additional_cert = None
    peer_validations = []
    logger.info('Testing TLS connection')
    x509, x509_certificate_chain, valid_subjects, protocol, cipher = util.get_certificates(host, port, cafiles=cafiles, client_pem=client_pem, client_ca=client_ca, tlsext=tlsext)
    sni_support = None
    if isinstance(x509, X509) and tlsext is True:
        logger.info('SNI supported')
        sni_support = True
    if not isinstance(x509, X509) and tlsext is False:
        logger.info('SNI not support')
        x509, x509_certificate_chain, extra_valid_subjects, protocol, cipher = util.get_certificates(host, port, cafiles=cafiles, client_pem=client_pem, client_ca=client_ca, tlsext=False)
        sni_support = False
        valid_subjects += extra_valid_subjects
    if not isinstance(x509, X509):
        raise ValidationError('Unable to negotiate a tls connection')
    if isinstance(x509, X509) and tlsext is False:
        logger.info('Checking SNI support')
        additional_cert, _, additional_valid_subjects, _, _ = util.get_certificates(host, port, cafiles=cafiles, client_pem=client_pem, client_ca=client_ca, tlsext=True)
        sni_support = isinstance(additional_cert, X509)
        valid_subjects += additional_valid_subjects
        
    logger.info('Checking server certificate')
    validator = Validator()
    validator.init_x509(x509)
    ca, path_length = util.get_basic_constraints(validator.certificate)
    if isinstance(ca, bool) and ca is True:
        raise ValidationFailure('server cert should not be a CA')
    validator.extract_metadata()
    validator.metadata.negotiated_cipher = cipher
    validator.metadata.negotiated_protocol = protocol
    validator.metadata.sni_support = sni_support
    if isinstance(path_length, int):
        validator.metadata.tlsext_basic_constraints_path_length = len(x509_certificate_chain) == path_length
    validator.verify(host, port)
    if len(valid_subjects) > 0 and util.key_usage_exists(validator.certificate, 'clientAuth') is True:
        pass
        # validator.client_authentication(valid_subjects, cafiles=cafiles, client_pem=client_pem, client_ca=client_ca)

    for cert in x509_certificate_chain:
        logger.info('Checking peer certificate')
        peer_validator = Validator()
        peer_validator.init_x509(cert)
        _, peer_path_length = util.get_basic_constraints(peer_validator.certificate)
        peer_validator.extract_metadata()
        if isinstance(peer_path_length, int):
            peer_validator.metadata.tlsext_basic_constraints_path_length = len(x509_certificate_chain) == peer_path_length
        peer_validator.verify(peer=True)
        peer_validations.append(peer_validator)
    validator.verify_chain(Validator.convert_x509_to_PEM(x509_certificate_chain))
    validations = peer_validations
    if isinstance(additional_cert, X509):
        additional_validator = Validator()
        additional_validator.init_x509(additional_cert)
        additional_validator.extract_metadata()
        if validator.metadata.certificate_common_name != additional_validator.metadata.certificate_common_name:
            logger.info('Checking additional SNI negotiated certificate')
            additional_validator.verify(host, port)
            tmp_valid = all([v.certificate_valid for v in peer_validations + [validator]] + [additional_validator.certificate_valid])
            if tmp_valid is False:
                logger.info('Checking peer certificate')
                additional_validator.verify_chain(Validator.convert_x509_to_PEM(x509_certificate_chain))
            validations.append(additional_validator)
        if len(valid_subjects) > 0 and util.key_usage_exists(additional_validator.certificate, 'clientAuth') is True:
            pass
            # additional_validator.client_authentication(valid_subjects, cafiles=cafiles, client_pem=client_pem, client_ca=client_ca)
    validations.append(validator)

    valid = all([v.certificate_valid for v in validations])
    return valid, validations
