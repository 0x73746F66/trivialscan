import json
import hashlib
import logging
from base64 import b64encode
from datetime import datetime
from pathlib import Path
import validators
import asn1crypto
from ssl import PEM_cert_to_DER_cert
from OpenSSL.crypto import X509, X509Name, dump_privatekey, dump_certificate, load_certificate, FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT, TYPE_RSA, TYPE_DSA, TYPE_DH, TYPE_EC
from cryptography.x509 import Certificate
from certvalidator.errors import PathValidationError, RevokedError, InvalidCertificateError, PathBuildingError
from validators.utils import ValidationFailure
from tlsverify import util
from tlsverify import exceptions
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
    tmp_path_prefix = '/tmp'

    def __init__(self, host :str = None, port :int = 443, client_pem :str = None, cafiles :list[str] = None) -> None:
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
        if host is not None:
            self.init_server(host=host, port=port)
            if client_pem is not None:
                client_pem = self.client_authentication(client_pem=client_pem, cafiles=cafiles)
            self.x509, self.certificate_chain, protocol, cipher, verifier_errors = util.get_certificates(host, port, cafiles=cafiles, client_pem=client_pem)
            self.load_verifier_errors(verifier_errors)
            logger.debug('added pyOpenSSL x509')
            self.metadata.negotiated_cipher = cipher
            self.metadata.negotiated_protocol = protocol
            if self.x509 is None or not self.certificate_chain:
                raise exceptions.ValidationError(exceptions.VALIDATION_ERROR_TLS_FAILED.format(host=host, port=port))
            self._pem = dump_certificate(FILETYPE_PEM, self.x509)
            logger.debug('added PEM bytes')
            self._der = PEM_cert_to_DER_cert(self._pem.decode())
            logger.debug('added ASN1/DER bytes')
            self.certificate = self.x509.to_cryptography()
            logger.debug('added lib cryptography object')
            self._pem_certificate_chain = util.convert_x509_to_PEM(self.certificate_chain)

    def __repr__ (self) -> str:
        certificate_verify_messages = '", "'.join(self.certificate_verify_messages)
        validation_checks = json.dumps(self.validation_checks)
        return f'<Validator(certificate_valid={self.certificate_valid}, ' +\
               f'certificate_chain_valid={self.certificate_chain_valid}, ' +\
               f'certificate_chain_validation_result={self.certificate_chain_validation_result}, ' +\
               f'certificate_verify_messages=["{certificate_verify_messages}"]", ' +\
               f'validation_checks={validation_checks}, ' +\
               'metadata=<tlsverify.util.Metadata>, ' +\
               'x509=<OpenSSL.crypto.X509>, ' +\
               '_pem=<bytes>, ' +\
               '_der=<bytes>, ' +\
               'certificate=<cryptography.x509.Certificate>)>'

    def __str__(self) -> str:
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
        fingerprints = ['certificate_sha256_fingerprint', 'certificate_sha1_fingerprint', 'certificate_md5_fingerprint', 'certificate_subject_key_identifier', 'certificate_authority_key_identifier']
        skip = ['certificate_san', 'certificate_extensions', 'subjectKeyIdentifier', 'authorityKeyIdentifier']
        kv = [
            ['certificate_valid', self.certificate_valid],
            ['certificate_chain_valid', self.certificate_chain_valid],
            ['certificate_chain_validation_result', self.certificate_chain_validation_result]
        ]
        kv += [['Error', err] for err in self.certificate_verify_messages]
        kv += [[f'Check {key}', self.validation_checks[key]] for key in self.validation_checks.keys()]
        kv += [[key, util.str_n_split(getattr(self.metadata, key)).upper() if key in fingerprints else getattr(self.metadata, key)] for key in list(vars(self.metadata).keys()) if key not in skip]
        kv += [[v['name'], any_to_string(v, ' ') if v['name'] not in v else any_to_string(v[v['name']], ' ')] for v in self.metadata.certificate_extensions if v['name'] not in skip]
        return tabulate(kv, tablefmt='tsv', disable_numparse=True, colalign=("right",))

    def init_server(self, host :str = None, port :int = 443):
        if not isinstance(port, int):
            raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
        if validators.domain(host) is not True:
            raise ValueError(f"provided an invalid domain {host}")
        self.metadata = util.Metadata(host=host, port=port)

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

    def cert_to_text(self) -> str:
        logger.debug('dump_certificate x509 FILETYPE_TEXT')
        return dump_certificate(FILETYPE_TEXT, self.x509).decode()

    def extract_metadata(self):
        if not hasattr(self, 'metadata') or self.metadata is None:
            self.metadata = util.Metadata(host=None)
        public_key = self.x509.get_pubkey()
        if public_key.type() == TYPE_RSA:
            self.metadata.certificate_public_key_type = 'RSA'
            self.metadata.certificate_rsa_private_key_pem = dump_privatekey(FILETYPE_PEM, public_key).decode()
        if public_key.type() == TYPE_DSA:
            self.metadata.certificate_public_key_type = 'DSA'
            self.metadata.certificate_dsa_private_key_pem = dump_privatekey(FILETYPE_PEM, public_key).decode()
        if public_key.type() == TYPE_DH:
            self.metadata.certificate_public_key_type = 'DH'
        if public_key.type() == TYPE_EC:
            self.metadata.certificate_public_key_type = 'EC'
        self.metadata.certificate_key_size = public_key.bits()
        self.metadata.certificate_serial_number_decimal = self.x509.get_serial_number()
        self.metadata.certificate_serial_number = util.convert_decimal_to_serial_bytes(self.x509.get_serial_number())
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
        if client_cert is None or not isinstance(client_cert, str):
            raise exceptions.ValidationError(exceptions.VALIDATION_ERROR_CLIENT_AUTHENTICATION)
        return client_cert

    def load_verifier_errors(self, errors :list[tuple[X509, int]]):
        if not isinstance(errors, list):
            return
        for cert, errno in errors:
            message = exceptions.X509_MESSAGES[errno]
            if errno in exceptions.X509_MESSAGES and self.x509.get_serial_number() == cert.get_serial_number() and message not in self.certificate_verify_messages:
                self.certificate_verify_messages.append(exceptions.X509_MESSAGES[errno])

    def verify(self, peer :bool = False, **kwargs) -> bool:
        if peer is False:
            logger.debug('Server certificate validations')
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

    @staticmethod
    def str_n_split(**kwargs):
        logger.warning(DeprecationWarning('Validator.str_n_split is now a util.str_n_split and will soon be removed.'), stack_info=True)
        return util.str_n_split(**kwargs)

    @staticmethod
    def convert_x509_to_PEM(**kwargs) -> list[bytes]:
        logger.warning(DeprecationWarning('Validator.convert_x509_to_PEM is now a util.convert_x509_to_PEM and will soon be removed.'), stack_info=True)
        return util.convert_x509_to_PEM(**kwargs)

def verify(host :str, port :int = 443, cafiles :list = None, tlsext :bool = False, client_pem :str = None, client_ca :str = None, tmp_path_prefix :str = '/tmp') -> tuple[bool,list[Validator]]:
    if not isinstance(port, int):
        raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    if not isinstance(client_pem, str) and client_pem is not None:
        raise TypeError(f"provided an invalid type {type(client_pem)} for client_pem, expected list")
    if not isinstance(cafiles, list) and cafiles is not None:
        raise TypeError(f"provided an invalid type {type(cafiles)} for cafiles, expected list")
    if not isinstance(tlsext, bool):
        raise TypeError(f"provided an invalid type {type(tlsext)} for tlsext, expected list")
    if not isinstance(tmp_path_prefix, str):
        raise TypeError(f"provided an invalid type {type(tmp_path_prefix)} for tmp_path_prefix, expected str")

    verifier_errors = []
    validator = Validator()
    if isinstance(tmp_path_prefix, str):
        validator.tmp_path_prefix = tmp_path_prefix
    validator.init_server(host, port)
    client_validated = False
    if client_pem is not None:
        client_pem = validator.client_authentication(client_pem=client_pem, cafiles=cafiles)
        client_validated = isinstance(client_pem, str)
    additional_cert = None
    peer_validations = []
    logger.info('Testing TLS connection')
    x509, x509_certificate_chain, protocol, cipher, verifier_err = util.get_certificates(host, port, cafiles=cafiles, client_pem=client_pem, client_ca=client_ca, tlsext=tlsext)
    verifier_errors += verifier_err
    sni_support = None
    if isinstance(x509, X509) and tlsext is True:
        logger.info('SNI supported')
        sni_support = True
    if not isinstance(x509, X509) and tlsext is False:
        logger.info('SNI not support')
        x509, x509_certificate_chain, protocol, cipher, verifier_err = util.get_certificates(host, port, cafiles=cafiles, client_pem=client_pem, client_ca=client_ca, tlsext=False)
        verifier_errors += verifier_err
        sni_support = False
    if not isinstance(x509, X509):
        raise exceptions.ValidationError('Unable to negotiate a tls connection')
    if isinstance(x509, X509) and tlsext is False:
        logger.info('Checking SNI support')
        additional_cert, _, _, _, verifier_err = util.get_certificates(host, port, cafiles=cafiles, client_pem=client_pem, client_ca=client_ca, tlsext=True)
        verifier_errors += verifier_err
        sni_support = isinstance(additional_cert, X509)

    logger.info('Checking server certificate')
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

    validator.load_verifier_errors(verifier_errors)
    validator.verify()
    # client_authentication would raise ValidationError or client_validated=True
    validator.metadata.certificate_client_authentication = util.key_usage_exists(validator.certificate, 'clientAuth') is True and client_validated
    for cert in x509_certificate_chain:
        logger.info('Checking peer certificate')
        peer_validator = Validator()
        peer_validator.init_x509(cert)
        _, peer_path_length = util.get_basic_constraints(peer_validator.certificate)
        peer_validator.extract_metadata()
        if isinstance(peer_path_length, int):
            peer_validator.metadata.tlsext_basic_constraints_path_length = len(x509_certificate_chain) == peer_path_length
        peer_validator.load_verifier_errors(verifier_errors)
        peer_validator.verify(peer=True)
        peer_validations.append(peer_validator)
    validator.verify_chain(util.convert_x509_to_PEM(x509_certificate_chain))
    validations = peer_validations
    if isinstance(additional_cert, X509):
        additional_validator = Validator()
        if isinstance(tmp_path_prefix, str):
            additional_validator.tmp_path_prefix = tmp_path_prefix
        additional_validator.init_x509(additional_cert)
        additional_validator.init_server(host)
        additional_validator.extract_metadata()
        # client_authentication would raise ValidationError or client_validated=True
        additional_validator.metadata.certificate_client_authentication = util.key_usage_exists(additional_validator.certificate, 'clientAuth') is True and client_validated
        additional_validator.load_verifier_errors(verifier_errors)
        if validator.metadata.certificate_common_name != additional_validator.metadata.certificate_common_name:
            logger.info('Checking additional SNI negotiated certificate')
            additional_validator.verify()
            tmp_valid = all([v.certificate_valid for v in peer_validations + [validator]] + [additional_validator.certificate_valid])
            if tmp_valid is False:
                logger.info('Checking peer certificate')
                additional_validator.verify_chain(util.convert_x509_to_PEM(x509_certificate_chain))
            validations.append(additional_validator)
    validations.append(validator)

    valid = all([v.certificate_valid for v in validations])
    return valid, validations
