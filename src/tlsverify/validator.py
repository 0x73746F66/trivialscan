import json
import hashlib
import logging
from os import path
from datetime import datetime
from pathlib import Path
import requests
from ssl import PEM_cert_to_DER_cert
from OpenSSL import SSL
from OpenSSL.crypto import X509,  X509Name, dump_privatekey, dump_certificate, load_certificate, FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT, TYPE_RSA, TYPE_DSA, TYPE_DH, TYPE_EC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import Certificate, extensions, PolicyInformation
from certvalidator.errors import PathValidationError, RevokedError, InvalidCertificateError, PathBuildingError
from dns.rrset import RRset
from tldextract import TLDExtract
from tlstrust import TrustStore, context
from tlstrust.stores.ccadb import __version__ as ccadb_version
from tlstrust.stores.java import __version__ as java_version
from tlstrust.stores.certifi import __version__ as certifi_version
from tlstrust.stores.linux import __version__ as linux_version
from tlstrust.stores.android_2_2 import __description__ as android2_2_version
from tlstrust.stores.android_2_3 import __description__ as android2_3_version
from tlstrust.stores.android_3 import __description__ as android3_version
from tlstrust.stores.android_4 import __description__ as android4_version
from tlstrust.stores.android_4_4 import __description__ as android4_4_version
from tlstrust.stores.android_7 import __description__ as android7_version
from tlstrust.stores.android_8 import __description__ as android8_version
from tlstrust.stores.android_9 import __description__ as android9_version
from tlstrust.stores.android_10 import __description__ as android10_version
from tlstrust.stores.android_11 import __description__ as android11_version
from tlstrust.stores.android_12 import __description__ as android12_version
from . import exceptions, util, constants, pci, fips, nist
from .transport import Transport
from .metadata import Metadata

__module__ = 'tlsverify.validator'
logger = logging.getLogger(__name__)

VALIDATION_CLIENT_AUTHENTICATION = 'client_authentication'
VALIDATION_CLIENT_AUTH_USAGE = 'client_certificate_permits_authentication_usage'
VALIDATION_NOT_EXPIRED = 'not_expired'
VALIDATION_ISSUED_PAST_TENSE = 'issued_past_tense'
VALIDATION_SUBJECT_CN_DEFINED = 'common_name_defined'
VALIDATION_SUBJECT_CN_VALID = 'common_name_valid'
VALIDATION_MATCH_HOSTNAME = 'match_hostname'
VALIDATION_NOT_SELF_SIGNED = 'not_self_signed'
VALIDATION_WEAK_SIG_ALGO = 'avoid_known_weak_signature_algorithm'
VALIDATION_WEAK_KEYS = 'avoid_known_weak_keys'
VALIDATION_DEPRECATED_TLS_PROTOCOLS = 'avoid_deprecated_protocols'
VALIDATION_DEPRECATED_DNSSEC_ALGO = 'avoid_deprecated_dnssec_algorithms'
VALIDATION_BASIC_CONSTRAINTS_CA = 'basic_constraints_ca'
VALIDATION_VALID_TLS_USAGE = 'certificate_valid_tls_usage'
VALIDATION_REVOCATION = 'not_revoked'
VALIDATION_ROOT_CA_TRUST = 'trusted_ca'
VALIDATION_VALID_DNSSEC = 'valid_dnssec'
VALIDATION_VALID_CAA = 'valid_caa'
VALIDATION_OCSP_STAPLE_SATISFIED = 'ocsp_staple_satisfied'
VALIDATION_OCSP_MUST_STAPLE_SATISFIED = 'ocsp_must_staple_satisfied'

class Validator:
    _pem :bytes
    _der :bytes
    x509 :X509
    certificate :Certificate
    tmp_path_prefix :str
    metadata :Metadata
    compliance_checks :dict
    validation_checks :dict
    certificate_verify_messages :list
    use_sqlite :bool

    def __init__(self, tmp_path_prefix :str = '/tmp', use_sqlite :bool = True) -> None:
        if not isinstance(tmp_path_prefix, str):
            raise TypeError(f'tmp_path_prefix of type {type(tmp_path_prefix)} not supported, str expected')
        tmp_path = Path(tmp_path_prefix)
        if not tmp_path.is_dir():
            raise AttributeError(f'tmp_path_prefix {tmp_path_prefix} is not a directory')
        self.tmp_path_prefix = tmp_path_prefix
        self.use_sqlite = use_sqlite
        self.compliance_checks = {}
        self.validation_checks = {}
        self.certificate_verify_messages = []
        self._pem = None
        self._der = None
        self.x509 = None
        self.certificate = None
        self.metadata = None
    
    @property
    def certificate_valid(self):
        validations = list(self.validation_checks.values())
        if not validations:
            return False
        return all(validations)

    def init_der(self, der :bytes):
        self._der = der
        self.x509 = load_certificate(FILETYPE_ASN1, der)
        self._pem = dump_certificate(FILETYPE_PEM, self.x509)
        self.certificate = self.x509.to_cryptography()
        self.extract_x509_metadata(self.x509)

    def init_pem(self, pem :bytes):
        self._pem = pem
        self.x509 = load_certificate(FILETYPE_PEM, pem)
        self._der = PEM_cert_to_DER_cert(self._pem.decode())
        self.certificate = self.x509.to_cryptography()
        self.extract_x509_metadata(self.x509)

    def init_x509(self, x509 :X509):
        self.x509 = x509
        self._pem = dump_certificate(FILETYPE_PEM, x509)
        self._der = PEM_cert_to_DER_cert(self._pem.decode())
        self.certificate = x509.to_cryptography()
        self.extract_x509_metadata(self.x509)

    def cert_to_text(self) -> str:
        return dump_certificate(FILETYPE_TEXT, self.x509).decode()

    def extract_x509_metadata(self, x509 :X509):
        if not hasattr(self, 'metadata') or not isinstance(self.metadata, Metadata):
            self.metadata = Metadata()
        self.metadata.certificate_version = x509.get_version()
        self.metadata.certificate_extensions = util.get_certificate_extensions(self.certificate)
        self.metadata.certificate_private_key_pem = None
        public_key = x509.get_pubkey()
        self._extract_public_key_info(public_key.type(), public_key, x509)
        self.metadata.certificate_serial_number_decimal = x509.get_serial_number()
        self.metadata.certificate_serial_number = util.convert_decimal_to_serial_bytes(x509.get_serial_number())
        self.metadata.certificate_serial_number_hex = '{0:#0{1}x}'.format(x509.get_serial_number(), 4)
        subject = x509.get_subject()
        self.metadata.certificate_subject = "".join("/{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())
        issuer: X509Name = x509.get_issuer()
        self.metadata.certificate_issuer = issuer.commonName
        self.metadata.certificate_issuer_country = issuer.countryName
        self.metadata.certificate_signature_algorithm = x509.get_signature_algorithm().decode('ascii')
        self.metadata.certificate_sha256_fingerprint = hashlib.sha256(self._der).hexdigest()
        self.metadata.certificate_sha1_fingerprint = hashlib.sha1(self._der).hexdigest()
        self.metadata.certificate_md5_fingerprint = hashlib.md5(self._der).hexdigest()
        self.metadata.certificate_spki_fingerprint = hashlib.sha256(self.x509.to_cryptography().public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        self.metadata.certificate_san = util.get_san(self.certificate)
        not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), constants.X509_DATE_FMT)
        not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), constants.X509_DATE_FMT)
        self.metadata.certificate_not_before = not_before.isoformat()
        self.metadata.certificate_not_after = not_after.isoformat()
        self.metadata.certificate_expired = x509.has_expired()
        self.metadata.certificate_common_name = util.extract_from_subject(self.certificate)
        self.metadata.certificate_subject_key_identifier, self.metadata.certificate_authority_key_identifier = util.get_ski_aki(self.certificate)
        if self.metadata.revocation_ocsp_must_staple is not True:
            for ext in self.metadata.certificate_extensions:
                if ext['name'] == 'TLSFeature' and 'rfc6066' in ext['features']:
                    self.metadata.revocation_ocsp_must_staple = True
        policies = []
        try:
            policies = self.certificate.extensions.get_extension_for_class(extensions.CertificatePolicies).value._policies
        except extensions.ExtensionNotFound:
            pass
        for policy in policies:
            if not isinstance(policy, PolicyInformation): continue
            if policy.policy_identifier._dotted_string in constants.VALIDATION_OID.keys():
                self.metadata.certificate_validation_type = constants.VALIDATION_TYPES[constants.VALIDATION_OID[policy.policy_identifier._dotted_string]]

    def _extract_public_key_info(self, key_type, public_key, x509):
        if key_type in [TYPE_RSA, TYPE_DSA]:
            self.metadata.certificate_public_key_type = 'RSA' if TYPE_RSA == key_type else 'DSA'
            self.metadata.certificate_private_key_pem = dump_privatekey(FILETYPE_PEM, public_key).decode()
            self.metadata.certificate_public_key_exponent = x509.to_cryptography().public_key().public_numbers().e
        if key_type in [TYPE_DH, TYPE_EC]:
            self.metadata.certificate_public_key_type = 'EC' if key_type == TYPE_EC else 'DH'
            self.metadata.certificate_public_key_curve = x509.to_cryptography().public_key().curve.name
        self.metadata.certificate_public_key_size = public_key.bits()

    def pcidss_compliant(self) -> bool:
        logger.debug('PCI DSS compliance validations')
        self.compliance_checks[pci.VALIDATION_WEAK_KEY] = self.metadata.certificate_public_key_size >= pci.WEAK_KEY_SIZE[self.metadata.certificate_public_key_type]
        if self.compliance_checks[pci.VALIDATION_WEAK_KEY] is False:
            if self.metadata.certificate_public_key_type == 'RSA':
                self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_WEAK_KEY_RSA)
            if self.metadata.certificate_public_key_type == 'DSA':
                self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_WEAK_KEY_DSA)
            if self.metadata.certificate_public_key_type == 'EC':
                self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_WEAK_KEY_EC)
            if self.metadata.certificate_public_key_type == 'DH':
                self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_WEAK_KEY_DH)

    def fips_compliant(self) -> bool:
        logger.debug('FIPS compliance validations')
        self.compliance_checks[fips.VALIDATION_WEAK_KEY] = self.metadata.certificate_public_key_size >= fips.WEAK_KEY_SIZE[self.metadata.certificate_public_key_type]
        if self.compliance_checks[fips.VALIDATION_WEAK_KEY] is False:
            if self.metadata.certificate_public_key_type == 'RSA':
                self.certificate_verify_messages.append(fips.FIPS_NON_COMPLIANCE_WEAK_KEY_RSA)
            if self.metadata.certificate_public_key_type == 'DSA':
                self.certificate_verify_messages.append(fips.FIPS_NON_COMPLIANCE_WEAK_KEY_DSA)
            if self.metadata.certificate_public_key_type == 'EC':
                self.certificate_verify_messages.append(fips.FIPS_NON_COMPLIANCE_WEAK_KEY_EC)
            if self.metadata.certificate_public_key_type == 'DH':
                self.certificate_verify_messages.append(fips.FIPS_NON_COMPLIANCE_WEAK_KEY_DH)

    def nist_compliant(self) -> bool:
        logger.debug('NIST compliance validations')
        self.compliance_checks[nist.VALIDATION_WEAK_KEY] = self.metadata.certificate_public_key_size >= nist.WEAK_KEY_SIZE[self.metadata.certificate_public_key_type]
        if self.compliance_checks[nist.VALIDATION_WEAK_KEY] is False:
            if self.metadata.certificate_public_key_type == 'RSA':
                self.certificate_verify_messages.append(nist.NIST_NON_COMPLIANCE_WEAK_KEY_RSA)
            if self.metadata.certificate_public_key_type == 'DSA':
                self.certificate_verify_messages.append(nist.NIST_NON_COMPLIANCE_WEAK_KEY_DSA)
            if self.metadata.certificate_public_key_type == 'EC':
                self.certificate_verify_messages.append(nist.NIST_NON_COMPLIANCE_WEAK_KEY_EC)
            if self.metadata.certificate_public_key_type == 'DH':
                self.certificate_verify_messages.append(nist.NIST_NON_COMPLIANCE_WEAK_KEY_DH)

    def verify(self) -> bool:
        logger.debug('Common certificate validations')
        not_after = datetime.fromisoformat(self.metadata.certificate_not_after)
        not_before = datetime.fromisoformat(self.metadata.certificate_not_before)
        self.validation_checks[VALIDATION_NOT_EXPIRED] = not_after > datetime.utcnow()
        if self.validation_checks[VALIDATION_NOT_EXPIRED] is False:
            self.certificate_verify_messages.append(util.date_diff(not_after))
        self.validation_checks[VALIDATION_ISSUED_PAST_TENSE] = not_before < datetime.utcnow()
        if self.validation_checks[VALIDATION_ISSUED_PAST_TENSE] is False:
            self.certificate_verify_messages.append(f'Will only be valid for use in {(datetime.utcnow() - self.metadata.certificate_not_before).days} days')
        self.validation_checks[VALIDATION_SUBJECT_CN_DEFINED] = self.metadata.certificate_common_name is not None
        self.validation_checks[VALIDATION_WEAK_SIG_ALGO] = self.metadata.certificate_signature_algorithm not in constants.KNOWN_WEAK_SIGNATURE_ALGORITHMS.keys()
        if self.validation_checks[VALIDATION_WEAK_SIG_ALGO] is False:
            self.certificate_verify_messages.append(constants.KNOWN_WEAK_SIGNATURE_ALGORITHMS[self.metadata.certificate_signature_algorithm])
        self.validation_checks[VALIDATION_WEAK_KEYS] = self.metadata.certificate_public_key_type not in constants.KNOWN_WEAK_KEYS.keys() or self.metadata.certificate_public_key_size > constants.WEAK_KEY_SIZE[self.metadata.certificate_public_key_type]
        if self.validation_checks[VALIDATION_WEAK_KEYS] is False:
            self.certificate_verify_messages.append(constants.KNOWN_WEAK_KEYS[self.metadata.certificate_public_key_type])
        self.possible_phish_or_malicious()
        self.known_compromise()
        self.pwnedkeys()
        self.metadata.revocation_crlite = util.crlite_revoked(db_path=path.join(self.tmp_path_prefix, ".crlite_db"), pem=self._pem, use_sqlite=self.use_sqlite)
        if self.metadata.revocation_crlite:
            self.validation_checks[VALIDATION_REVOCATION] = False

    def possible_phish_or_malicious(self) -> bool:
        logger.debug('Impersonation, C2, other detections')
        bad_cn = ['localhost', 'portswigger']
        bad_san = ['localhost', 'lvh.me']
        for cn in bad_cn:
            check = self.metadata.certificate_common_name
            if not check:
                continue
            if cn in check.lower():
                self.metadata.possible_phish_or_malicious = True
        subject_ou = util.extract_from_subject(self.certificate, 'organizationalUnitName')
        if subject_ou:
            bad_ou = ['charlesproxy', 'portswigger']
            for ou in bad_ou:
                if ou in subject_ou.lower():
                    self.metadata.possible_phish_or_malicious = True
        for bad in bad_san:
            for san in self.metadata.certificate_san:
                if bad in san:
                    self.metadata.possible_phish_or_malicious = True
        if self.metadata.certificate_private_key_pem and 'BEGIN PRIVATE KEY' in self.metadata.certificate_private_key_pem:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_EXPOSED_PRIVATE_KEY)
        return self.metadata.possible_phish_or_malicious

    def known_compromise(self) -> bool:
        logger.debug('Check known compromised certificates')
        self.metadata.certificate_known_compromised = False
        if self.metadata.certificate_sha1_fingerprint.upper() in constants.COMPROMISED_SHA1.keys():
            self.metadata.certificate_known_compromised = True
        return self.metadata.certificate_known_compromised

    def pwnedkeys(self) -> bool:
        url = f"https://v1.pwnedkeys.com/{self.metadata.certificate_spki_fingerprint.lower()}.jws"
        logger.info(f'Check {url}')
        resp = requests.get(url)
        logger.debug(resp.text)
        if 'That key does not appear to be pwned' in resp.text:
            self.metadata.certificate_key_compromised = False
        if resp.status_code == 200:
            self.metadata.certificate_key_compromised = True
        return self.metadata.certificate_key_compromised

class RootCertValidator(Validator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        certificate_verify_messages = '", "'.join(self.certificate_verify_messages)
        validation_checks = json.dumps(self.validation_checks)
        return f'<Validator(certificate_valid={self.certificate_valid}, ' +\
              f'certificate_verify_messages=["{certificate_verify_messages}"]", ' +\
              f'validation_checks={validation_checks}, ' +\
               'metadata=<tlsverify.metadata.Metadata>, ' +\
               'x509=<OpenSSL.crypto.X509>, ' +\
               '_pem=<bytes>, ' +\
               '_der=<bytes>, ' +\
               'certificate=<cryptography.x509.Certificate>)>'

    def pcidss_compliant(self) -> bool:
        super().pcidss_compliant()
        self.compliance_checks[pci.VALIDATION_CA_TRUST] = all([self.metadata.trust_ccadb, self.metadata.trust_android, self.metadata.trust_certifi, self.metadata.trust_java, self.metadata.trust_linux])
        if self.compliance_checks[pci.VALIDATION_CA_TRUST] is False:
            self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_CA_TRUST)

    def fips_compliant(self) -> bool:
        super().fips_compliant()
        self.compliance_checks[fips.VALIDATION_CA_TRUST] = all([self.metadata.trust_ccadb, self.metadata.trust_android, self.metadata.trust_certifi, self.metadata.trust_java, self.metadata.trust_linux])
        if self.compliance_checks[fips.VALIDATION_CA_TRUST] is False:
            self.certificate_verify_messages.append(fips.FIPS_NON_COMPLIANCE_CA_TRUST)

    def nist_compliant(self) -> bool:
        super().nist_compliant()
        self.compliance_checks[nist.VALIDATION_CA_TRUST] = all([self.metadata.trust_ccadb, self.metadata.trust_android, self.metadata.trust_certifi, self.metadata.trust_java, self.metadata.trust_linux])
        if self.compliance_checks[nist.VALIDATION_CA_TRUST] is False:
            self.certificate_verify_messages.append(nist.NIST_NON_COMPLIANCE_CA_TRUST)

    def verify_trust(self, trust_store :TrustStore):
        DEFAULT_STATUS = 'No Root CA Certificate in the {platform} Trust Store'
        self.metadata.trust_ccadb_status = DEFAULT_STATUS.format(platform='CCADB')
        self.metadata.trust_android_status = DEFAULT_STATUS.format(platform='Android')
        self.metadata.trust_java_status = DEFAULT_STATUS.format(platform='Java')
        self.metadata.trust_linux_status = DEFAULT_STATUS.format(platform='Linux')
        self.metadata.trust_certifi_status = DEFAULT_STATUS.format(platform='Python')

        expired_text = ' EXPIRED'
        if trust_store.exists(context.SOURCE_CCADB):
            self.metadata.trust_ccadb_status = f'In Common CA Database {ccadb_version} (Mozilla, Microsoft, and Apple)'
            if trust_store.expired_in_store(context.SOURCE_CCADB):
                self.metadata.trust_ccadb_status += expired_text
        if trust_store.exists(context.SOURCE_JAVA):
            self.metadata.trust_java_status = f'In Java Root CA Trust Store {java_version}'
            if trust_store.expired_in_store(context.SOURCE_JAVA):
                self.metadata.trust_java_status += expired_text
        if trust_store.exists(context.SOURCE_LINUX):
            self.metadata.trust_linux_status = f'In Linux {linux_version} Root CA Trust Store'
            if trust_store.expired_in_store(context.SOURCE_LINUX):
                self.metadata.trust_linux_status += expired_text
        if trust_store.exists(context.SOURCE_CERTIFI):
            self.metadata.trust_certifi_status = f'In Python {certifi_version} Root CA Trust Store (Django, requests, urllib, and anything based from these)'
            if trust_store.expired_in_store(context.SOURCE_CERTIFI):
                self.metadata.trust_certifi_status += expired_text

        android_stores = []
        if trust_store.exists(context.PLATFORM_ANDROID2_2):
            android_status = f'{android2_2_version} {"Trusted" if trust_store.android2_2 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID2_2):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android2_2_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID2_3):
            android_status = f'{android2_3_version} {"Trusted" if trust_store.android2_3 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID2_3):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android2_3_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID3):
            android_status = f'{android3_version} {"Trusted" if trust_store.android3 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID3):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android3_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID4_4):
            android_status = f'{android4_4_version} {"Trusted" if trust_store.android4_4 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID4_4):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android4_4_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID7):
            android_status = f'{android7_version} {"Trusted" if trust_store.android7 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID7):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android7_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID8):
            android_status = f'{android8_version} {"Trusted" if trust_store.android8 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID8):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android8_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID9):
            android_status = f'{android9_version} {"Trusted" if trust_store.android9 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID9):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android9_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID10):
            android_status = f'{android10_version} {"Trusted" if trust_store.android10 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID10):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android10_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID11):
            android_status = f'{android11_version} {"Trusted" if trust_store.android11 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID11):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android11_version} Not Present')
        if trust_store.exists(context.PLATFORM_ANDROID12):
            android_status = f'{android12_version} {"Trusted" if trust_store.android12 else "Not Trusted"}'
            if trust_store.expired_in_store(context.PLATFORM_ANDROID12):
                android_status += expired_text
            android_stores.append(android_status)
        else:
            android_stores.append(f'{android12_version} Not Present')

        self.metadata.trust_android_status = "\n".join(android_stores)
        self.metadata.trust_ccadb = trust_store.ccadb
        self.metadata.trust_java = trust_store.java
        self.metadata.trust_android = all([trust_store.android7, trust_store.android8, trust_store.android9, trust_store.android10, trust_store.android11, trust_store.android12])
        self.metadata.trust_linux = trust_store.linux
        self.metadata.trust_certifi = trust_store.certifi

class PeerCertValidator(Validator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        certificate_verify_messages = '", "'.join(self.certificate_verify_messages)
        validation_checks = json.dumps(self.validation_checks)
        return f'<Validator(certificate_valid={self.certificate_valid}, ' +\
              f'certificate_verify_messages=["{certificate_verify_messages}"]", ' +\
              f'validation_checks={validation_checks}, ' +\
               'metadata=<tlsverify.metadata.Metadata>, ' +\
               'x509=<OpenSSL.crypto.X509>, ' +\
               '_pem=<bytes>, ' +\
               '_der=<bytes>, ' +\
               'certificate=<cryptography.x509.Certificate>)>'

class LeafCertValidator(Validator):
    _pem_certificate_chain :list
    peer_validations :list[PeerCertValidator]
    certificate_chain :list[X509]
    transport :Transport
    _root_certs :list

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.transport = None
        self.certificate_chain_valid = None
        self.certificate_chain_validation_result = None
        self._pem_certificate_chain = []
        self.peer_validations = []
        self.certificate_chain = []

    def __repr__(self) -> str:
        certificate_verify_messages = '", "'.join(self.certificate_verify_messages)
        validation_checks = json.dumps(self.validation_checks)
        return (
            f'<Validator(certificate_valid={self.certificate_valid}, '
            + f'certificate_chain_valid={self.certificate_chain_valid}, '
            + f'certificate_chain_validation_result={self.certificate_chain_validation_result}, '
            + f'certificate_verify_messages=["{certificate_verify_messages}"]", '
            + f'validation_checks={validation_checks}, '
            + 'metadata=<tlsverify.metadata.Metadata>, '
            + 'transport=<tlsverify.transport.Transport>, '
            + 'x509=<OpenSSL.crypto.X509>, '
            + '_pem=<bytes>, '
            + '_der=<bytes>, '
            + 'certificate=<cryptography.x509.Certificate>)>'
        )

    def mount(self, transport :Transport):
        if not isinstance(transport, Transport):
            raise TypeError(f"provided an invalid type {type(transport)} for transport, expected an instance of <tlsverify.transport.Transport>")
        self.transport = transport
        self.extract_transport_metadata(transport)
        if isinstance(transport.server_certificate, X509):
            self.init_x509(transport.server_certificate)
        self.parse_openssl_errors(transport.verifier_errors)

    def extract_transport_metadata(self, transport :Transport):
        if not hasattr(self, 'metadata') or not isinstance(self.metadata, Metadata):
            self.metadata = Metadata(
                host=transport.host,
                port=transport.port
            )
        self._pem_certificate_chain = util.convert_x509_to_PEM(transport.certificate_chain)
        self.certificate_chain = transport.certificate_chain
        self.metadata.peer_address = transport.peer_address
        self.metadata.revocation_ocsp_stapling = transport.ocsp_stapling
        self.metadata.revocation_ocsp_must_staple = transport.ocsp_must_staple
        self.metadata.revocation_ocsp_status = transport.ocsp_certificate_status
        self.metadata.revocation_ocsp_response = transport.ocsp_response_status
        self.metadata.revocation_ocsp_reason = transport.ocsp_revocation_reason
        self.metadata.revocation_ocsp_time = transport.ocsp_revocation_time
        self.metadata.offered_ciphers = transport.ciphers
        self.metadata.client_certificate_expected = transport.client_certificate_expected is True
        self.metadata.negotiated_cipher_bits = transport.negotiated_cipher_bits
        self.metadata.negotiated_cipher = transport.negotiated_cipher
        if self.metadata.negotiated_cipher and any(self.metadata.negotiated_cipher.startswith(c) for c in ['DHE', 'ECDHE']):
            self.metadata.forward_anonymity = True
        if self.metadata.negotiated_cipher not in constants.NOT_KNOWN_WEAK_CIPHERS:
            self.metadata.weak_cipher = True
        if self.metadata.negotiated_cipher in constants.STRONG_CIPHERS:
            self.metadata.strong_cipher = True
        self.metadata.negotiated_protocol = transport.negotiated_protocol
        self.metadata.sni_support = transport.sni_support
        self.metadata.tls_version_intolerance = transport.tls_version_intolerance
        self.metadata.tls_version_intolerance_versions = transport.tls_version_intolerance_versions
        self.metadata.tls_version_interference = transport.tls_version_interference
        self.metadata.tls_version_interference_versions = transport.tls_version_interference_versions
        self.metadata.tls_long_handshake_intolerance = transport.long_handshake_intolerance
        self.metadata.offered_tls_versions = list(set(transport.offered_tls_versions))
        self.metadata.session_resumption_caching = transport.session_cache_mode in ['session_resumption_both', 'session_resumption_caching']
        self.metadata.session_resumption_tickets = transport.session_tickets
        self.metadata.session_resumption_ticket_hint = transport.session_ticket_hints
        self.metadata.compression_support = self.header_exists(name='content-encoding', includes_value='gzip')
        self.metadata.client_renegotiation = transport.client_renegotiation
        self.metadata.scsv = transport.tls_downgrade is False # modern network tools such as F5 try to hide cause and blend in making scsv undetectable directly but a downgrade can still be observed
        self.metadata.preferred_protocol = transport.preferred_protocol
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
        http_statuses = [505]
        if transport.http1_support:
            http_statuses.append(transport.http1_code)
        if transport.http1_1_support:
            http_statuses.append(transport.http1_1_code)
        if transport.client_certificate_expected:
            http_statuses.append(511)
        self.metadata.http_status_code = min(http_statuses)
        self.metadata.http1_support = transport.http1_support
        self.metadata.http1_1_support = transport.http1_1_support
        self.metadata.http2_support = transport.http2_support
        self.http2_cleartext_support = transport.http2_cleartext_support

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

    def parse_openssl_errors(self, errors :list[tuple[X509, int]]):
        if not isinstance(errors, list):
            return
        for cert, errno in errors:
            message = exceptions.X509_MESSAGES[errno]
            if errno in exceptions.X509_MESSAGES and self.x509.get_serial_number() == cert.get_serial_number() and message not in self.certificate_verify_messages:
                self.certificate_verify_messages.append(exceptions.X509_MESSAGES[errno])

    def pcidss_compliant(self):
        super().pcidss_compliant()
        if self.metadata.negotiated_protocol is None:
            return
        self.compliance_checks[pci.VALIDATION_WEAK_CIPHER] = not self.metadata.weak_cipher or self.metadata.negotiated_cipher_bits >= pci.WEAK_CIPHER_BITS
        if self.compliance_checks[pci.VALIDATION_WEAK_CIPHER] is False:
            self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_CIPHER)
        self.compliance_checks[pci.VALIDATION_WEAK_PROTOCOL] = self.metadata.negotiated_protocol not in constants.WEAK_PROTOCOL.keys()
        if self.compliance_checks[pci.VALIDATION_WEAK_PROTOCOL] is False:
            self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_WEAK_PROTOCOL)
        self.compliance_checks[pci.VALIDATION_DEPRECATED_ALGO] = not self.metadata.dnssec_algorithm or self.metadata.dnssec_algorithm not in constants.WEAK_DNSSEC_ALGORITHMS.keys()
        if self.compliance_checks[pci.VALIDATION_DEPRECATED_ALGO] is False:
            self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_WEAK_ALGORITHMS)
        self.compliance_checks[pci.VALIDATION_KNOWN_VULN_SESSION_RESUMPTION] = all([
            not self.metadata.session_resumption_tickets or constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] == SSL.TLS1_3_VERSION,
            not self.metadata.session_resumption_caching or constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] == SSL.TLS1_3_VERSION,
        ])
        self.compliance_checks[pci.VALIDATION_KNOWN_VULN_RENEGOTIATION] = not self.metadata.client_renegotiation
        self.compliance_checks[pci.VALIDATION_KNOWN_VULN_COMPRESSION] = not self.metadata.compression_support
        if any([
                self.compliance_checks[pci.VALIDATION_KNOWN_VULN_RENEGOTIATION],
                self.compliance_checks[pci.VALIDATION_KNOWN_VULN_COMPRESSION],
                self.compliance_checks[pci.VALIDATION_KNOWN_VULN_SESSION_RESUMPTION],
            ]):
            self.certificate_verify_messages.append(pci.PCIDSS_NON_COMPLIANCE_KNOWN_VULNERABILITIES)

    def fips_compliant(self):
        super().fips_compliant()
        if self.metadata.negotiated_protocol is None:
            return
        if constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] not in [SSL.TLS1_2_VERSION, SSL.TLS1_3_VERSION]:
            self.compliance_checks[fips.VALIDATION_MTLS] = not self.metadata.client_certificate_expected

        self.compliance_checks[fips.VALIDATION_WEAK_PROTOCOL] = self.metadata.negotiated_protocol not in ['SSLv2 (0x02ff)', 'SSLv3 (0x0300)']
        if self.compliance_checks[fips.VALIDATION_WEAK_PROTOCOL] is False:
            self.certificate_verify_messages.append(fips.FIPS_NON_COMPLIANCE_WEAK_PROTOCOL)
            self.compliance_checks[fips.VALIDATION_WEAK_CIPHER] = False
            self.certificate_verify_messages.append(fips.FIPS_NON_COMPLIANCE_CIPHER)
        else:
            ok_cipher = self.metadata.negotiated_cipher_bits >= fips.WEAK_CIPHER_BITS
            if ok_cipher and constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] == SSL.TLS1_2_VERSION:
                ok_cipher = all(c in self.metadata.negotiated_cipher for c in fips.ALLOWED_CIPHERS)
            if ok_cipher and constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] in [SSL.TLS1_VERSION, SSL.TLS1_1_VERSION]:
                ok_cipher = all(c in self.metadata.negotiated_cipher for c in fips.ALLOWED_DEPRECATED_TLS_CIPHERS)
            self.compliance_checks[fips.VALIDATION_WEAK_CIPHER] = ok_cipher
            if self.compliance_checks[fips.VALIDATION_WEAK_CIPHER] is False:
                self.certificate_verify_messages.append(fips.FIPS_NON_COMPLIANCE_CIPHER)

    def nist_compliant(self):
        # sourcery skip: extract-duplicate-method, extract-method, remove-redundant-if, split-or-ifs
        # sourcery will add bloat here, this is massively more concise logic then theirs
        super().nist_compliant()
        if self.metadata.negotiated_protocol is None:
            return
        if constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] in [SSL.TLS1_2_VERSION, SSL.TLS1_3_VERSION]:
            self.compliance_checks[nist.VALIDATION_WEAK_PROTOCOL] = True
            self.compliance_checks[nist.VALIDATION_MTLS] = self.metadata.client_certificate_expected
            ok_cipher = self.metadata.negotiated_cipher_bits >= nist.WEAK_CIPHER_BITS
            if ok_cipher and constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] == SSL.TLS1_2_VERSION:
                ok_cipher = all(c in self.metadata.negotiated_cipher for c in nist.ALLOWED_CIPHERS)
            self.compliance_checks[nist.VALIDATION_WEAK_CIPHER] = ok_cipher
            if self.compliance_checks[nist.VALIDATION_WEAK_CIPHER] is False:
                self.certificate_verify_messages.append(nist.NIST_NON_COMPLIANCE_CIPHER)
        else:
            self.compliance_checks[nist.VALIDATION_WEAK_PROTOCOL] = False
            self.certificate_verify_messages.append(nist.NIST_NON_COMPLIANCE_WEAK_PROTOCOL)
            self.compliance_checks[nist.VALIDATION_WEAK_CIPHER] = False
            self.certificate_verify_messages.append(nist.NIST_NON_COMPLIANCE_CIPHER)

    def verify(self) -> bool:
        super().verify()
        tldext = TLDExtract(cache_dir='/tmp')(f'http://{self.metadata.host}')
        ca = util.get_basic_constraints(self.certificate)
        logger.debug('Server certificate validations')
        self.validation_checks[VALIDATION_BASIC_CONSTRAINTS_CA] = True
        if self.transport.client_certificate_expected:
            self.validation_checks[VALIDATION_CLIENT_AUTH_USAGE] = isinstance(self.transport.client_certificate, X509) and util.key_usage_exists(self.transport.client_certificate.to_cryptography(), 'clientAuth') is True
            self.validation_checks[VALIDATION_CLIENT_AUTHENTICATION] = self.transport.client_certificate_match and isinstance(self.transport.client_certificate, X509) and self.transport.negotiated_protocol is not None and util.key_usage_exists(self.certificate, 'clientAuth') is True
            if self.validation_checks[VALIDATION_CLIENT_AUTHENTICATION] is False:
                self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_CLIENT_AUTHENTICATION)
        if isinstance(ca, bool) and ca is True:
            self.validation_checks[VALIDATION_BASIC_CONSTRAINTS_CA] = False
            self.certificate_verify_messages.append('Server (leaf) certificates should not be a CA, it could enable impersonation attacks')
        self.validation_checks[VALIDATION_VALID_TLS_USAGE] = util.key_usage_exists(self.certificate, 'digital_signature') is True and util.key_usage_exists(self.certificate, 'serverAuth') is True
        self.validation_checks[VALIDATION_SUBJECT_CN_VALID] = False if not self.metadata.certificate_common_name else util.validate_common_name(self.metadata.certificate_common_name, self.metadata.host) is True
        self.validation_checks[VALIDATION_MATCH_HOSTNAME] = util.match_hostname(self.metadata.host, self.certificate)
        self.metadata.certificate_is_self_signed = util.is_self_signed(self.certificate)
        self.validation_checks[VALIDATION_NOT_SELF_SIGNED] = self.metadata.certificate_is_self_signed is False
        if self.metadata.revocation_ocsp_stapling is True:
            self.validation_checks[VALIDATION_OCSP_STAPLE_SATISFIED] = False
            if self.metadata.revocation_ocsp_response is not None:
                self.validation_checks[VALIDATION_OCSP_STAPLE_SATISFIED] = True
        if self.metadata.revocation_ocsp_must_staple is True:
            self.validation_checks[VALIDATION_OCSP_MUST_STAPLE_SATISFIED] = False
            if self.metadata.revocation_ocsp_status == util.OCSP_CERT_STATUS[0]:
                self.validation_checks[VALIDATION_OCSP_MUST_STAPLE_SATISFIED] = True
        if self.metadata.certification_authority_authorization:
            self.validation_checks[VALIDATION_VALID_CAA] = util.caa_valid(self.metadata.host, self.x509, self.certificate_chain)
        if self.metadata.dnssec:
            self.validation_checks[VALIDATION_VALID_DNSSEC] = util.dnssec_valid(self.metadata.host)
            if self.validation_checks[VALIDATION_VALID_DNSSEC] is False and tldext.registered_domain != self.metadata.host:
                self.validation_checks[VALIDATION_VALID_DNSSEC] = util.dnssec_valid(tldext.registered_domain)
                if self.validation_checks[VALIDATION_VALID_DNSSEC]:
                    self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_DNSSEC_TARGET)
                else:
                    self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_DNSSEC_REGISTERED_DOMAIN)
        else:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_DNSSEC_MISSING)
        self.validation_checks[VALIDATION_DEPRECATED_DNSSEC_ALGO] = self.metadata.dnssec_algorithm not in constants.WEAK_DNSSEC_ALGORITHMS.keys()
        if self.validation_checks[VALIDATION_DEPRECATED_DNSSEC_ALGO] is False:
            self.certificate_verify_messages.append(constants.WEAK_DNSSEC_ALGORITHMS[self.metadata.dnssec_algorithm])
        if self.metadata.certificate_validation_type == constants.VALIDATION_TYPES['DV']:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_CERTIFICATE_VALIDATION_TYPE)
        if not self.metadata.certification_authority_authorization:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_CERTIFICATION_AUTHORITY_AUTHORIZATION)
        self.verify_negotiated_tls()
        return self.certificate_valid

    def verify_negotiated_tls(self):
        if self.metadata.negotiated_protocol is None:
            return
        if self.metadata.preferred_protocol != self.metadata.negotiated_protocol:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_SCSV.format(protocol=self.metadata.preferred_protocol, fallback=self.metadata.negotiated_protocol))
        if self.metadata.certificate_is_self_signed:
            self.validation_checks[VALIDATION_ROOT_CA_TRUST] = False
            self.certificate_verify_messages.append('The CA is not properly imported as a trusted CA into the browser, Chrome based browsers will block visitors and show them ERR_CERT_AUTHORITY_INVALID')
        self.validation_checks[VALIDATION_DEPRECATED_TLS_PROTOCOLS] = self.metadata.negotiated_protocol not in constants.WEAK_PROTOCOL.keys()
        if self.validation_checks[VALIDATION_DEPRECATED_TLS_PROTOCOLS] is False:
            self.certificate_verify_messages.append(constants.WEAK_PROTOCOL[self.metadata.negotiated_protocol])
        if self.metadata.session_resumption_caching and constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] != SSL.TLS1_3_VERSION:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_SESSION_RESUMPTION_CACHING)
        if self.metadata.session_resumption_caching and constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] == SSL.TLS1_3_VERSION:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_SESSION_RESUMPTION_CACHING_TLS1_3)
        if self.metadata.session_resumption_tickets and constants.PROTOCOL_TEXT_MAP[self.metadata.negotiated_protocol] != SSL.TLS1_3_VERSION:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_SESSION_RESUMPTION_TICKETS)
        if self.metadata.client_renegotiation:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_CLIENT_RENEGOTIATION)
        if self.metadata.compression_support:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_COMPRESSION_SUPPORT)
        interference_versions = ''.join(self.metadata.tls_version_interference_versions)
        current_version = 'TLSv1.3'
        if '0x304' in interference_versions:
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_VERSION_INTERFERENCE_CURRENT.format(current_version=current_version))
        if '0x303' in interference_versions:
            common_version = 'TLSv1.2'
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_VERSION_INTERFERENCE_COMMON.format(current_version=current_version, common_version=common_version))
        if '0x302' in interference_versions:
            old_version = 'TLSv1.1'
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_VERSION_INTERFERENCE_OLD.format(old_version=old_version))
        elif any(['0x301' in interference_versions, '0x300' in interference_versions, '0x2ff' in interference_versions]):
            self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_VERSION_INTERFERENCE_OBSOLETE)

    def _get_root_certs(self, trust_store :TrustStore):
        contexts = [
            context.PLATFORM_ANDROID7,
            context.PLATFORM_ANDROID8,
            context.PLATFORM_ANDROID9,
            context.PLATFORM_ANDROID10,
            context.PLATFORM_ANDROID11,
            context.PLATFORM_ANDROID12,
            context.SOURCE_CCADB,
            context.SOURCE_JAVA,
            context.SOURCE_LINUX,
            context.SOURCE_CERTIFI
        ]
        for context_type in contexts:
            try:
                yield trust_store.get_certificate_from_store(context_type=context_type)
            except FileExistsError:
                pass

    def _validate_roots(self, trust_store :TrustStore):
        for cert in self._get_root_certs(trust_store):
            if cert.get_serial_number() in self._root_certs:
                continue
            root_validator = RootCertValidator()
            root_validator.init_x509(cert)
            root_validator.metadata.certificate_root_ca = True
            root_validator.verify()
            root_validator.verify_trust(trust_store)
            root_validator.pcidss_compliant()
            root_validator.fips_compliant()
            root_validator.nist_compliant()
            self.peer_validations.append(root_validator)
            self._root_certs.append(cert.get_serial_number())

    def verify_chain(self, progress_bar :callable = lambda *args: None) -> bool:
        if not self._pem_certificate_chain:
            return False

        validator_key_usage, validator_extended_key_usage = util.gather_key_usages(self.certificate)
        validation_result = f'Validated: {",".join(validator_key_usage + validator_extended_key_usage)}'
        try:
            logger.debug('certificate chain validation')
            util.validate_certificate_chain(self._der, self._pem_certificate_chain, validator_key_usage, validator_extended_key_usage)
        except RevokedError as ex:
            logger.debug(ex, stack_info=True)
            self.validation_checks[VALIDATION_REVOCATION] = False
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

        self.certificate_chain_validation_result = validation_result
        self.certificate_chain_valid = self.certificate_chain_valid is not False

        progress_bar()
        def map_peers(peers :list[X509]):
            peers_map = {}
            for cert in peers:
                ski, aki = util.get_ski_aki(cert.to_cryptography())
                if ski is None or aki is None:
                    logger.warning(f'Certificate {cert.get_subject()} has no SKI or AKI')
                peers_map[ski] = [cert, aki]
            return peers_map

        peer_lookup = map_peers(self.certificate_chain)
        for cert in self.certificate_chain:
            progress_bar()
            if cert.get_serial_number() == self.x509.get_serial_number():
                continue
            ca, _ = util.get_basic_constraints(cert.to_cryptography())
            peer_validator = PeerCertValidator()
            peer_validator.init_x509(cert)
            peer_validator.metadata.certificate_intermediate_ca = ca is True
            trust_store = None
            checked_peer_as_root = False
            if peer_validator.metadata.certificate_authority_key_identifier is None:
                trust_store = TrustStore(authority_key_identifier=peer_validator.metadata.certificate_subject_key_identifier)
                checked_peer_as_root = True
            elif peer_validator.metadata.certificate_authority_key_identifier not in peer_lookup.keys():
                trust_store = TrustStore(authority_key_identifier=peer_validator.metadata.certificate_authority_key_identifier)
            if isinstance(trust_store, TrustStore):
                logger.info(f'Checking for Root CA issuer {cert.get_issuer()} with SKI {peer_validator.metadata.certificate_authority_key_identifier}')
                self._root_certs = []
                self.validation_checks[VALIDATION_ROOT_CA_TRUST] = trust_store.is_trusted
                if any([
                        trust_store.exists(context.SOURCE_CCADB),
                        trust_store.exists(context.SOURCE_JAVA),
                        trust_store.exists(context.SOURCE_LINUX),
                        trust_store.exists(context.SOURCE_CERTIFI),
                        trust_store.exists(context.PLATFORM_ANDROID7),
                        trust_store.exists(context.PLATFORM_ANDROID8),
                        trust_store.exists(context.PLATFORM_ANDROID9),
                        trust_store.exists(context.PLATFORM_ANDROID10),
                        trust_store.exists(context.PLATFORM_ANDROID11),
                        trust_store.exists(context.PLATFORM_ANDROID12),
                    ]):
                    self._validate_roots(trust_store)
                if not self.validation_checks[VALIDATION_ROOT_CA_TRUST]:
                    self.certificate_verify_messages.append(exceptions.VALIDATION_ERROR_MISSING_ROOT_CA_AKI.format(serial_number=peer_validator.metadata.certificate_serial_number_hex))
                else:
                    checked_peer_as_root = checked_peer_as_root is True

            if not checked_peer_as_root:
                peer_validator.verify()
                self.validation_checks[VALIDATION_REVOCATION] = self.validation_checks.get(VALIDATION_REVOCATION) is not False
                peer_validator.pcidss_compliant()
                peer_validator.fips_compliant()
                peer_validator.nist_compliant()
                self.peer_validations.append(peer_validator)

        return all([self.certificate_valid, self.certificate_chain_valid])

    def extract_x509_metadata(self, x509 :X509):
        super().extract_x509_metadata(x509)
        tlsa_ext = util.get_extensions_by_oid(self.x509.to_cryptography(), constants.TLSA_EXTENSION_OID)
        tlsa_dns = util.get_tlsa_answer(self.metadata.host)
        self.metadata.tlsa = isinstance(tlsa_ext, extensions.Extension) or tlsa_dns is not None
        self.metadata.certification_authority_authorization = util.caa_exist(self.metadata.host)
        answer :list[RRset] = util.get_dnssec_answer(self.metadata.host)
        if answer:
            self.metadata.dnssec = True
            algorithm = int(answer[0].to_text().split()[6])
            self.metadata.dnssec_algorithm = algorithm if algorithm not in constants.DNSSEC_ALGORITHMS else constants.DNSSEC_ALGORITHMS[algorithm]
