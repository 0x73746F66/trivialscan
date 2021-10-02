import hashlib
import logging
from datetime import datetime
from base64 import b64encode
from dataclasses import asdict
from ssl import PEM_cert_to_DER_cert
import validators
import asn1crypto
from OpenSSL.crypto import X509, X509Name, dump_certificate, load_certificate, FILETYPE_PEM, FILETYPE_ASN1, TYPE_RSA, TYPE_DSA, TYPE_DH, TYPE_EC
from cryptography.x509 import extensions, Certificate, SubjectAlternativeName, DNSName
from certvalidator.errors import PathValidationError, RevokedError, InvalidCertificateError, PathBuildingError
from tlsverify import util
from tlsverify.exceptions import ValidationError

__module__ = 'tlsverify'

logger = logging.getLogger(__name__)

class Validator:
    _pem :bytes
    _der :bytes
    x509 :X509
    certificate :Certificate
    _pem_certificate_chain :list
    _X509_certificate_chain :list
    metadata :util.Metadata

    def __init__(self, host :str = None, port :int = 443) -> None:
        self.certificate_valid = False
        self.validation_checks = {}
        self.certificate_verify_messages = []
        self.certificate_chain_valid = None
        self.certificate_chain_validation_result = None
        if host is not None:
            self.x509, self._X509_certificate_chain, self.metadata = util.get_certificates(host, port)
            if self.x509 is None or not self._X509_certificate_chain:
                raise ValidationError(f'Unable to negotiate a TLS socket connection with server at {host}:{port} to obtain the Certificate')
            self._pem = dump_certificate(FILETYPE_PEM, self.x509)
            self._der = PEM_cert_to_DER_cert(self._pem.decode())
            self.certificate = self.x509.to_cryptography()
            self._pem_certificate_chain = []
            for cert in self._X509_certificate_chain:
                self._pem_certificate_chain.append(dump_certificate(FILETYPE_PEM, cert))

    def get_metadata(self) -> dict:
        return asdict(self.metadata)

    def init_der(self, der :bytes):
        self._der = der
        self.x509 = load_certificate(FILETYPE_ASN1, der)
        self._pem = dump_certificate(FILETYPE_PEM, self.x509)
        self.certificate = self.x509.to_cryptography()

    def init_pem(self, pem :bytes):
        self._pem = pem
        self.x509 = load_certificate(FILETYPE_PEM, pem)
        self._der = PEM_cert_to_DER_cert(self._pem.decode())
        self.certificate = self.x509.to_cryptography()

    def init_x509(self, x509 :X509):
        self.x509 = x509
        self._pem = dump_certificate(FILETYPE_PEM, x509)
        self._der = PEM_cert_to_DER_cert(self._pem.decode())
        self.certificate = x509.to_cryptography()

    def extract_metadata(self):
        if not hasattr(self, 'metadata'):
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
        self.metadata.certificate_serial_number = self.x509.get_serial_number()
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
        try:
            self.metadata.certificate_san = self.certificate.extensions.get_extension_for_class(SubjectAlternativeName).value.get_values_for_type(DNSName)
        except extensions.ExtensionNotFound:
            pass
        not_before = datetime.strptime(self.x509.get_notBefore().decode('ascii'), util.X509_DATE_FMT)
        not_after = datetime.strptime(self.x509.get_notAfter().decode('ascii'), util.X509_DATE_FMT)
        self.metadata.certificate_not_before = not_before.isoformat()
        self.metadata.certificate_not_after = not_after.isoformat()
        self.metadata.certificate_common_name = util.extract_certificate_common_name(self.certificate)
        for ext in self.metadata.certificate_extensions:
            if ext['name'] == 'TLSFeature' and 'rfc6066' in ext['features']:
                self.metadata.revocation_ocsp_stapling = True
                self.metadata.revocation_ocsp_must_staple = True

    def verify(self, host :str = None, port :int = None, server_cert :bool = True) -> bool:
        self.extract_metadata()
        if server_cert and isinstance(host, str):
            self.metadata.host = host
        if server_cert and validators.domain(self.metadata.host) is not True:
            raise ValueError(f"provided an invalid domain {host}")
        if server_cert and isinstance(port, int):
            self.metadata.port = port
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
        if server_cert:
            self.validation_checks['common_name_valid'] = util.validate_common_name(self.metadata.certificate_common_name, self.metadata.host) is True
            self.validation_checks['match_hostname'] = util.match_hostname(self.metadata.host, self.certificate)
            self.metadata.certificate_is_self_signed = util.is_self_signed(self.certificate)
            self.validation_checks['not_self_signed'] = self.metadata.certificate_is_self_signed is False
            if self.metadata.certificate_is_self_signed:
                self.validation_checks['trusted_CA'] = False
                self.certificate_verify_messages.append('The CA is not properly imported as a trusted CA into the browser, Chrome based browsers will block visitors and show them ERR_CERT_AUTHORITY_INVALID')
        self.certificate_valid = all(list(self.validation_checks.values()))
        return self.certificate_valid

    def verify_chain(self, certificate_chain :list[bytes] = None) -> bool:
        if certificate_chain is not None:
            self._pem_certificate_chain = certificate_chain
        self.metadata.certificate_extensions, validator_key_usage, validator_extended_key_usage = util.gather_key_usages(self.certificate)
        try:
            util.validate_certificate_chain(self._der, self._pem_certificate_chain, validator_key_usage, validator_extended_key_usage)
        except RevokedError as ex:
            self.validation_checks['not_revoked'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except InvalidCertificateError as ex:
            self.validation_checks['certificate_chain_valid'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except PathValidationError as ex:
            self.validation_checks['certificate_chain_valid'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except PathBuildingError as ex:
            self.validation_checks['certificate_chain_valid'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except Exception as ex:
            logger.exception(ex)
            self.validation_checks['certificate_chain_valid'] = False
            self.certificate_chain_validation_result = str(ex)

        if self.certificate_chain_validation_result is None:
            self.certificate_chain_valid = True
            self.certificate_chain_validation_result = f'Validated: {",".join(validator_key_usage + validator_extended_key_usage)}'

        self.certificate_valid = all(list(self.validation_checks.values()))
        return self.certificate_valid and self.certificate_chain_valid

def verify(host :str, port :int = 443, cafiles :list = None, tlsext :bool = False) -> tuple[bool,list[Validator]]:
    validations = []
    x509, x509_certificate_chain, _ = util.get_certificates(host, port, cafiles, tlsext=tlsext)
    validator = Validator()
    validator.init_x509(x509)
    validator.verify(host, port)
    certificate_chain = []
    for cert in x509_certificate_chain:
        certificate_chain.append(dump_certificate(FILETYPE_PEM, cert))
        peer_validator = Validator()
        peer_validator.init_x509(cert)
        peer_validator.verify(server_cert=False)
        validations.append(peer_validator)

    validator.verify_chain(certificate_chain)
    validations.append(validator)
    valid = all([v.certificate_valid for v in validations])
    return valid, validations
