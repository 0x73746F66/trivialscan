import logging
from datetime import datetime
from socket import socket
from dataclasses import asdict
from ssl import create_default_context, SSLCertVerificationError, Purpose
from OpenSSL.crypto import X509, dump_certificate, FILETYPE_PEM
import validators
from cryptography.x509 import Certificate
from certvalidator.errors import PathValidationError, RevokedError, InvalidCertificateError, PathBuildingError
from tlsverify import util
from tlsverify.exceptions import ValidationError

__module__ = 'tlsverify'

logger = logging.getLogger(__name__)

class Validator:
    _pem :bytes
    x509 :X509
    certificate :Certificate
    _pem_certificate_chain :list
    _X509_certificate_chain :list
    metadata :util.Metadata
    certificate_valid = False
    validation_checks = {}
    certificate_verify_messages = []
    certificate_chain_valid = False
    certificate_chain_validation_result = None

    def __init__(self, host :str, port :int = 443) -> None:
        self.x509, self._X509_certificate_chain, self.metadata = util.get_certificates(host, port)
        if self.x509 is None or not self._X509_certificate_chain:
            raise ValidationError(f'Unable to negotiate a TLS socket connection with server at {host}:{port} to obtain the Certificate')
        self._pem = dump_certificate(FILETYPE_PEM, self.x509)
        self.certificate = self.x509.to_cryptography()
        self.metadata = util.extract_metadata(self.x509, self.metadata)
        self._pem_certificate_chain = []
        for cert in self._X509_certificate_chain:
            self._pem_certificate_chain.append(dump_certificate(FILETYPE_PEM, cert))

    def verify(self) -> bool:
        not_after = datetime.fromisoformat(self.metadata.certificate_not_after)
        not_before = datetime.fromisoformat(self.metadata.certificate_not_before)
        self.validation_checks['not_expired'] = not_after > datetime.utcnow()
        if self.validation_checks['not_expired'] is False:
            self.certificate_verify_messages.append(f'Expired {(datetime.utcnow() - not_after).days} days ago' if not_after < datetime.utcnow() else f'Valid for {(not_after - datetime.utcnow()).days} days')
        self.validation_checks['issued_past_tense'] = not_before < datetime.utcnow()
        if self.validation_checks['issued_past_tense'] is False:
            self.certificate_verify_messages.append(f'Will only be valid for use in {(datetime.utcnow() - self.metadata.certificate_not_before).days} days')
        self.validation_checks['common_name_valid'] = validators.domain(self.metadata.certificate_common_name) is True
        self.validation_checks['common_name_defined'] = self.metadata.certificate_common_name is not None
        self.validation_checks['match_hostname'] = util.match_hostname(self.metadata.host, self.certificate)
        self.validation_checks['avoid_known_weak_signature_algorithm'] = self.metadata.certificate_signature_algorithm not in util.KNOWN_WEAK_SIGNATURE_ALGORITHMS.keys()
        if self.validation_checks['avoid_known_weak_signature_algorithm'] is False:
            self.certificate_verify_messages.append(util.KNOWN_WEAK_SIGNATURE_ALGORITHMS[self.metadata.certificate_signature_algorithm])
        self.validation_checks['avoid_known_weak_keys'] = self.metadata.certificate_public_key_type not in util.KNOWN_WEAK_KEYS.keys() or self.metadata.certificate_key_size > util.WEAK_KEY_SIZE[self.metadata.certificate_public_key_type]
        if self.validation_checks['avoid_known_weak_keys'] is False:
            self.certificate_verify_messages.append(util.KNOWN_WEAK_KEYS[self.metadata.certificate_public_key_type])

        self.metadata.certificate_is_self_signed = False
        try:
            ctx1 = create_default_context(purpose=Purpose.CLIENT_AUTH)
            with ctx1.wrap_socket(socket(), server_hostname=self.metadata.host) as sock:
                sock.connect((self.metadata.host, 443))

        except SSLCertVerificationError as ex:
            self.certificate_verify_messages.append(ex.verify_message)
            if 'self signed certificate' in ex.verify_message:
                self.validation_checks['trusted_CA'] = False
                self.certificate_verify_messages.append('The CA is not properly imported as a trusted CA into the browser, Chrome based browsers will block visitors and show them ERR_CERT_AUTHORITY_INVALID')
                self.metadata.certificate_is_self_signed = True

        self.metadata.certificate_extensions, validator_key_usage, validator_extended_key_usage = util.gather_key_usages(self.certificate)
        try:
            util.validate_certificate_chain(self._pem, self._pem_certificate_chain, validator_key_usage, validator_extended_key_usage)
        except RevokedError as ex:
            self.validation_checks['not_revoked'] = False
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except InvalidCertificateError as ex:
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except PathValidationError as ex:
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except PathBuildingError as ex:
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except Exception as ex:
            logger.exception(ex)
            self.certificate_chain_validation_result = str(ex)

        if self.certificate_chain_validation_result is None:
            self.certificate_chain_valid = True
            self.certificate_chain_validation_result = f'Validated: {",".join(validator_key_usage + validator_extended_key_usage)}'

        self.certificate_valid = all(list(self.validation_checks.values()))
        return self.certificate_valid and self.certificate_chain_valid

    def get_metadata(self) -> dict:
        return asdict(self.metadata)
