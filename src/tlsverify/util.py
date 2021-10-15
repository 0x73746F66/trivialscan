import logging
import string
from datetime import datetime
import random
from urllib.request import urlretrieve
from binascii import hexlify
from pathlib import Path
from cryptography import x509
from cryptography.x509 import Certificate, extensions, SubjectAlternativeName, DNSName
from OpenSSL import SSL
from OpenSSL.crypto import X509, FILETYPE_PEM, dump_certificate
from certvalidator import CertificateValidator, ValidationContext
import validators


__module__ = 'tlsverify.util'

logger = logging.getLogger(__name__)

VALIDATION_OID = {
    '2.16.840.1.114414.1.7.23.1': 'DV',
    '1.3.6.1.4.1.46222.1.10': 'DV',
    '1.3.6.1.4.1.34697.1.1': 'EV',
    '2.16.840.1.113839.0.6.3': 'EV',
    '2.16.792.3.0.3.1.1.5': 'EV',
    '1.3.6.1.4.1.5237.1.1.3': 'EV',
    '2.16.840.1.101.3.2.1.1.5': 'EV',
    '1.3.6.1.4.1.30360.3.3.3.3.4.4.3.0': 'EV',
    '1.3.6.1.4.1.46222.1.1': 'EV',
    '1.3.6.1.4.1.311.60': 'EV',
    '1.3.6.1.4.1.48679.100': 'EV',
    '1.3.6.1.4.1.55594.1.1.1': 'EV',
    '1.3.6.1.4.1.4788.2.200.1': 'EV',
    '1.3.6.1.4.1.4788.2.202.1': 'EV',
    '1.3.6.1.4.1.31247.1.3': 'EV',
    '1.3.6.1.4.1.52331.2': 'EV',
    '2.16.840.1.114414.1.7.23.2': 'OV',
    '2.16.792.3.0.3.1.1.2': 'OV',
    '1.3.6.1.4.1.46222.1.20': 'OV',
    '2.23.140.1.2.1': 'DV',
    '2.23.140.1.2.2': 'OV',
    '2.23.140.1.2.3': 'EV',
}
X509_DATE_FMT = r'%Y%m%d%H%M%SZ'
WEAK_KEY_SIZE = {
    'RSA': 1024,
    'DSA': 2048,
    'EC': 160,
}
KNOWN_WEAK_KEYS = {
    'RSA': '2000: Factorization of a 512-bit RSA Modulus, essentially derive a private key knowing only the public key. Verified bt EFF in 2001. Later in 2009 factorization of up to 1024-bit keys',
    'DSA': '1999: HPL Laboratories demonstrated lattice attacks on DSA, a non-trivial example of the known message attack that is a total break and message forgery technique. 2010 Dimitrios Poulakis demonstrated a lattice reduction technique for single or multiple message forgery',
    'EC': '2010 Dimitrios Poulakis demonstrated a lattice reduction technique to attack ECDSA for single or multiple message forgery',
}
KNOWN_WEAK_SIGNATURE_ALGORITHMS = {
    'sha1WithRSAEncryption': 'Macquarie University Australia 2009: identified vulnerabilities to collision attacks, later in 2017 Marc Stevens demonstrated collision proofs',
    'md5WithRSAEncryption': 'Arjen Lenstra and Benne de Weger 2005: vulnerable to hash collision attacks',
    'md2WithRSAEncryption': 'Rogier, N. and Chauvaud, P. in 1995: vulnerable to collision, later preimage resistance, and second-preimage resistance attacks were demonstrated at BlackHat 2008 by Mark Twain',
}
OPENSSL_VERSION_LOOKUP = {
    768: 'SSLv3',
    769: 'TLSv1',
    770: 'TLSv1.1',
    771: 'TLSv1.2',
    772: 'TLSv1.3',
}
WEAK_PROTOCOL = {
    'SSLv2': 'SSLv2 Deprecated in 2011 (rfc6176) with undetectable manipulator-in-the-middle exploits',
    'SSLv3': 'SSLv3 Deprecated in 2015 (rfc7568) mainly due to POODLE, a manipulator-in-the-middle exploit',
    'TLSv1': 'TLSv1 2018 deprecated by PCI Council. Also in 2018, Apple, Google, Microsoft, and Mozilla jointly announced deprecation. Officially deprecated in 2020 (rfc8996)',
    'TLSv1.1': 'TLSv1.1 No longer supported by Firefox 24 or newer and Chrome 29 or newer. Deprecated in 2020 (rfc8996)',
}
OCSP_RESP_STATUS = {
    0: 'Successful',
    1: 'Malformed Request',
    2: 'Internal Error',
    3: 'Try Later',
    4: 'Signature Required',
    5: 'Unauthorized',
}
OCSP_CERT_STATUS = {
    0: 'Good',
    1: 'Revoked',
    2: 'Unknown',
}
SESSION_CACHE_MODE = {
    SSL.SESS_CACHE_OFF: 'no caching',
    SSL.SESS_CACHE_CLIENT: 'session_resumption_tickets',
    SSL.SESS_CACHE_SERVER: 'session_resumption_caching',
    SSL.SESS_CACHE_BOTH: 'session_resumption_both',
}
NOT_KNOWN_WEAK_CIPHERS = [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES256-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES128-SHA256',
    'DHE-DSS-AES256-GCM-SHA384',
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES256-SHA256',
    'DHE-DSS-AES256-SHA256',
    'DHE-DSS-AES128-GCM-SHA256',
    'DHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES128-SHA256',
    'DHE-DSS-AES128-SHA256',
]
STRONG_CIPHERS = [
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_CCM_8_SHA256',
    'TLS_AES_128_CCM_SHA2',
]


def filter_valid_files_urls(inputs :list[str], tmp_path_prefix :str = '/tmp'):
    ret = set()
    for test in inputs:
        if test is None:
            return False
        file_path = Path(test)
        if file_path.is_file() is False and validators.url(test) is not True:
            return False
        if file_path.is_file():
            ret.add(test)
            continue
        if validators.url(test) is True:
            r = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
            local_path = f'{tmp_path_prefix}/tlsverify-{r}'
            try:
                urlretrieve(test, local_path)
            except Exception as ex:
                logger.error(ex, stack_info=True)
            file_path = Path(local_path)
            if not file_path.is_file():
                return False
            ret.add(local_path)
    return list(ret)

def convert_decimal_to_serial_bytes(decimal :int):
    # add leading 0
    a = "0%x" % decimal
    # force even num bytes, remove leading 0 if necessary
    b = a[1:] if len(a)%2==1 else a
    return format(':'.join(s.encode('utf8').hex().lower() for s in b))

def is_self_signed(cert :Certificate) -> bool:
    certificate_is_self_signed = False
    authority_key_identifier = None
    subject_key_identifier = None
    try:
        authority_key_identifier = hexlify(cert.extensions.get_extension_for_class(extensions.AuthorityKeyIdentifier).value.key_identifier).decode('utf-8')
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
        certificate_is_self_signed = True
    try:
        subject_key_identifier = hexlify(cert.extensions.get_extension_for_class(extensions.SubjectKeyIdentifier).value.digest).decode('utf-8')
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
        certificate_is_self_signed = True
    if subject_key_identifier == authority_key_identifier:
        certificate_is_self_signed = True
    return certificate_is_self_signed

def get_san(cert :Certificate) -> list:
    san = []
    try:
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value.get_values_for_type(DNSName)
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    return san

def get_basic_constraints(cert :Certificate) -> tuple[bool, int]:
    basic_constraints = None
    try:
        basic_constraints = cert.extensions.get_extension_for_class(extensions.BasicConstraints).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    if not isinstance(basic_constraints, extensions.BasicConstraints):
        return None, None
    return basic_constraints.ca, basic_constraints.path_length

def key_usage_exists(cert :Certificate, key :str) -> bool:
    key_usage = None
    ext_key_usage = None
    try:
        key_usage = cert.extensions.get_extension_for_class(extensions.KeyUsage).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    try:
        ext_key_usage = cert.extensions.get_extension_for_class(extensions.ExtendedKeyUsage).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    if key_usage is None and ext_key_usage is None:
        logger.warning('no key usages could not be found')
        return False
    if isinstance(key_usage, extensions.KeyUsage) and hasattr(key_usage, key) and getattr(key_usage, key) is True:
        return True
    if isinstance(ext_key_usage, extensions.ExtendedKeyUsage) and key in [usage._name for usage in ext_key_usage if hasattr(usage, '_name')]:
        return True
    return False

def get_valid_certificate_extensions(cert :Certificate) -> list[extensions.Extension]:
    certificate_extensions = []
    for ext in cert.extensions:
        if isinstance(ext.value, extensions.UnrecognizedExtension):
            continue
        certificate_extensions.append(ext.value)
    return certificate_extensions

def get_certificate_extensions(cert :Certificate) -> list[dict]:
    certificate_extensions = []
    for ext in cert.extensions:
        data = {
            'critical': ext.critical,
            'name': ext.oid._name # pylint: disable=protected-access
        }
        if isinstance(ext.value, extensions.UnrecognizedExtension):
            continue
        if isinstance(ext.value, extensions.CRLNumber):
            data[data['name']] = ext.value.crl_number
        if isinstance(ext.value, extensions.AuthorityKeyIdentifier):
            data[data['name']] = hexlify(ext.value.key_identifier).decode('utf-8')
            data['authority_cert_issuer'] = ', '.join([x.value for x in ext.value.authority_cert_issuer or []])
            data['authority_cert_serial_number'] = ext.value.authority_cert_serial_number
        if isinstance(ext.value, extensions.SubjectKeyIdentifier):
            data[data['name']] = hexlify(ext.value.digest).decode('utf-8')
        if isinstance(ext.value, (extensions.AuthorityInformationAccess, extensions.SubjectInformationAccess)):
            data[data['name']] = []
            for description in ext.value:
                data[data['name']].append({
                    'access_location': description.access_location.value,
                    'access_method': description.access_method._name, # pylint: disable=protected-access
                })
        if isinstance(ext.value, extensions.BasicConstraints):
            data['ca'] = ext.value.ca
            data['path_length'] = ext.value.path_length
        if isinstance(ext.value, extensions.DeltaCRLIndicator):
            data[data['name']] = ext.value.crl_number
        if isinstance(ext.value, (extensions.CRLDistributionPoints, extensions.FreshestCRL)):
            data[data['name']] = []
            for distribution_point in ext.value:
                data[data['name']].append({
                    'full_name': ', '.join([x.value for x in distribution_point.full_name or []]),
                    'relative_name': distribution_point.relative_name,
                    'reasons': distribution_point.reasons,
                    'crl_issuer': ', '.join([x.value for x in distribution_point.crl_issuer or []]),
                })
        if isinstance(ext.value, extensions.PolicyConstraints):
            data['policy_information'] = []
            data['user_notices'] = []
            for info in ext.value:
                if hasattr(info, 'require_explicit_policy'):
                    data['policy_information'].append({
                        'require_explicit_policy': info.require_explicit_policy,
                        'inhibit_policy_mapping': info.inhibit_policy_mapping,
                    })
                if hasattr(info, 'notice_reference'):
                    data['user_notices'].append({
                        'organization': info.notice_reference.organization,
                        'notice_numbers': info.notice_reference.notice_numbers,
                        'explicit_text': info.explicit_text,
                    })
        if isinstance(ext.value, extensions.ExtendedKeyUsage):
            data[data['name']] = [x._name for x in ext.value or []] # pylint: disable=protected-access
        if isinstance(ext.value, extensions.TLSFeature):
            data[data['name']] = []
            for feature in ext.value:
                if feature.value == 5:
                    data[data['name']].append('OCSP Must-Staple (rfc6066)')
                if feature.value == 17:
                    data[data['name']].append('multiple OCSP responses (rfc6961)')
        if isinstance(ext.value, extensions.InhibitAnyPolicy):
            data[data['name']] = ext.value.skip_certs
        if isinstance(ext.value, extensions.KeyUsage):
            data[data['name']] = []
            data['digital_signature'] = ext.value.digital_signature
            if ext.value.digital_signature:
                data[data['name']].append('digital_signature')
            data['content_commitment'] = ext.value.content_commitment
            if ext.value.content_commitment:
                data[data['name']].append('content_commitment')
            data['key_encipherment'] = ext.value.key_encipherment
            if ext.value.key_encipherment:
                data[data['name']].append('key_encipherment')
            data['data_encipherment'] = ext.value.data_encipherment
            if ext.value.data_encipherment:
                data[data['name']].append('data_encipherment')
            data['key_agreement'] = ext.value.key_agreement
            if ext.value.key_agreement:
                data[data['name']].append('key_agreement')
                data['decipher_only'] = ext.value.decipher_only
                if ext.value.decipher_only:
                    data[data['name']].append('decipher_only')
                data['encipher_only'] = ext.value.encipher_only
                if ext.value.encipher_only:
                    data[data['name']].append('encipher_only')
            data['key_cert_sign'] = ext.value.key_cert_sign
            if ext.value.key_cert_sign:
                data[data['name']].append('key_cert_sign')
            data['crl_sign'] = ext.value.crl_sign
            if ext.value.crl_sign:
                data[data['name']].append('crl_sign')
        if isinstance(ext.value, extensions.NameConstraints):
            data['permitted_subtrees'] = [x.value for x in ext.value.permitted_subtrees or []]
            data['excluded_subtrees'] = [x.value for x in ext.value.excluded_subtrees or []]
        if isinstance(ext.value, extensions.SubjectAlternativeName):
            data[data['name']] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.IssuerAlternativeName):
            data[data['name']] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.CertificateIssuer):
            data[data['name']] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.CRLReason):
            data[data['name']] = ext.value.reason
        if isinstance(ext.value, extensions.InvalidityDate):
            data[data['name']] = ext.value.invalidity_date
        if isinstance(ext.value, (extensions.PrecertificateSignedCertificateTimestamps, extensions.SignedCertificateTimestamps)):
            data[data['name']] = []
            for signed_cert_timestamp in ext.value:
                data[data['name']].append({
                    'version': signed_cert_timestamp.version.name,
                    'log_id': hexlify(signed_cert_timestamp.log_id).decode('utf-8'),
                    'timestamp': signed_cert_timestamp.timestamp,
                    'pre_certificate': signed_cert_timestamp.entry_type.value == 1,
                })
        if isinstance(ext.value, extensions.OCSPNonce):
            data[data['name']] = ext.value.nonce
        if isinstance(ext.value, extensions.IssuingDistributionPoint):
            data['full_name'] = ext.value.full_name
            data['relative_name'] = ext.value.relative_name
            data['only_contains_user_certs'] = ext.value.only_contains_user_certs
            data['only_contains_ca_certs'] = ext.value.only_contains_ca_certs
            data['only_some_reasons'] = ext.value.only_some_reasons
            data['indirect_crl'] = ext.value.indirect_crl
            data['only_contains_attribute_certs'] = ext.value.only_contains_attribute_certs
        certificate_extensions.append(data)
    return certificate_extensions

def gather_key_usages(cert :Certificate) -> tuple[list, list]:
    validator_key_usage = []
    validator_extended_key_usage = []
    for ext in get_valid_certificate_extensions(cert):
        if isinstance(ext, extensions.UnrecognizedExtension):
            continue
        ext_name = ext.oid._name
        if isinstance(ext, extensions.ExtendedKeyUsage):
            extended_usages = [x._name for x in ext or []] # pylint: disable=protected-access
            if 'serverAuth' in extended_usages:
                validator_extended_key_usage.append('server_auth')
        if isinstance(ext, extensions.TLSFeature):
            for feature in ext:
                if feature.value == 5:
                    validator_extended_key_usage.append('ocsp_signing')
                if feature.value == 17:
                    validator_extended_key_usage.append('ocsp_signing')
        if isinstance(ext, extensions.KeyUsage):
            if ext.digital_signature:
                validator_key_usage.append('digital_signature')
            if ext.content_commitment:
                validator_key_usage.append('content_commitment')
            if ext.key_encipherment:
                validator_key_usage.append('key_encipherment')
            if ext.data_encipherment:
                validator_key_usage.append('data_encipherment')
            if ext.key_agreement:
                validator_key_usage.append('key_agreement')
                if ext.decipher_only:
                    validator_key_usage.append('decipher_only')
                if ext.encipher_only:
                    validator_key_usage.append('encipher_only')
            if ext.key_cert_sign:
                validator_key_usage.append('key_cert_sign')
            if ext.crl_sign:
                validator_key_usage.append('crl_sign')

    return validator_key_usage, validator_extended_key_usage

def get_ski_aki(cert :Certificate) -> tuple[str, str]:
    ski = None
    aki = None
    for ext in get_certificate_extensions(cert):
        if ext['name'] == 'subjectKeyIdentifier':
            ski = ext[ext['name']]
        if ext['name'] == 'authorityKeyIdentifier':
            aki = ext[ext['name']]

    return ski, aki

def extract_from_subject(cert :Certificate, name :str = 'commonName'):
    for fields in cert.subject:
        current = str(fields.oid)
        if name in current:
            return fields.value
    return None

def validate_common_name(common_name :str, host :str) -> bool:
    if not isinstance(common_name, str):
        raise ValueError("invalid certificate_common_name provided")
    if not isinstance(host, str):
        raise ValueError("invalid host provided")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    if common_name.startswith('*.'):
        common_name_suffix = common_name.replace('*.', '')
        if validators.domain(common_name_suffix) is not True:
            return False
        return common_name_suffix == host or host.endswith(common_name_suffix)
    return validators.domain(common_name) is True

def match_hostname(host :str, cert :Certificate) -> bool:
    if not isinstance(host, str):
        raise ValueError("invalid host provided")
    if not isinstance(cert, Certificate):
        raise ValueError("invalid Certificate provided")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    certificate_san = []
    try:
        certificate_san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    valid_common_name = False
    wildcard_hosts = set()
    domains = set()
    for fields in cert.subject:
        current = str(fields.oid)
        if "commonName" in current:
            valid_common_name = validate_common_name(fields.value, host)
    for san in certificate_san:
        if san.startswith('*.'):
            wildcard_hosts.add(san)
        else:
            domains.add(san)
    matched_wildcard = False
    for wildcard in wildcard_hosts:
        check = wildcard.replace('*', '')
        if host.endswith(check):
            matched_wildcard = True
            break

    return valid_common_name is True and (matched_wildcard is True or host in domains)

def validate_certificate_chain(der :bytes, pem_certificate_chain :list, validator_key_usage :list, validator_extended_key_usage :list):
    # TODO perhaps remove certvalidator, consider once merged: https://github.com/pyca/cryptography/issues/2381
    ctx = ValidationContext(allow_fetching=True, revocation_mode='hard-fail', weak_hash_algos=set(["md2", "md5", "sha1"]))
    validator = CertificateValidator(der, validation_context=ctx, intermediate_certs=pem_certificate_chain)
    return validator.validate_usage(
        key_usage=set(validator_key_usage),
        extended_key_usage=set(validator_extended_key_usage),
    )

def str_n_split(input :str, n :int = 2, delimiter :str = ' '):
    if not isinstance(input, str): return input
    return delimiter.join([input[i:i+n] for i in range(0, len(input), n)])

def convert_x509_to_PEM(certificate_chain :list) -> list[bytes]:
    pem_certs = []
    for cert in certificate_chain:
        if not isinstance(cert, X509):
            raise AttributeError(f'convert_x509_to_PEM expected OpenSSL.crypto.X509, got {type(cert)}')
        pem_certs.append(dump_certificate(FILETYPE_PEM, cert))
    return pem_certs

def date_diff(comparer :datetime) -> str:
    interval = comparer - datetime.utcnow()
    if interval.days < -1:
        return f"Expired {int(abs(interval.days))} days ago"
    if interval.days == -1:
        return f"Expired yesterday"
    if interval.days == 0:
        return "Expires today"
    if interval.days == 1:
        return "Expires tomorrow"
    if interval.days > 365:
        return f"Expires in {interval.days} days ({int(round(interval.days/365))} years)"
    if interval.days > 1:
        return f"Expires in {interval.days} days"
