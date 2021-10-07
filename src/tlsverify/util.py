import logging
import string
import random
from urllib.request import urlretrieve
from dataclasses import dataclass, field
from binascii import hexlify
from socket import socket, AF_INET, SOCK_STREAM
from pathlib import Path
from cryptography import x509
from cryptography.x509 import Certificate, extensions, SubjectAlternativeName, DNSName
from OpenSSL import SSL
from OpenSSL.crypto import X509, FILETYPE_PEM, X509Name, dump_certificate
from certifi import where
from certvalidator import CertificateValidator, ValidationContext
import validators
import idna
from . import exceptions

__module__ = 'tlsverify.util'

logger = logging.getLogger(__name__)
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

@dataclass
class Metadata:
    host :str = field(default_factory=str)
    certificate_public_key_type :str = field(default_factory=str)
    certificate_key_size :int = field(default_factory=int)
    certificate_serial_number :str = field(default_factory=str)
    certificate_serial_number_decimal :int = field(default_factory=str)
    certificate_serial_number_hex :str = field(default_factory=str)
    certificate_subject :str = field(default_factory=str)
    certificate_issuer :str = field(default_factory=str)
    certificate_issuer_country :str = field(default_factory=str)
    certificate_signature_algorithm :str = field(default_factory=str)
    certificate_pin_sha256 :str = field(default_factory=str)
    certificate_sha256_fingerprint :str = field(default_factory=str)
    certificate_sha1_fingerprint :str = field(default_factory=str)
    certificate_md5_fingerprint :str = field(default_factory=str)
    certificate_not_before :str = field(default_factory=str)
    certificate_not_after :str = field(default_factory=str)
    certificate_common_name :str = field(default_factory=str)
    certificate_san :list = field(default_factory=list)
    certificate_subject_key_identifier :str = field(default_factory=str)
    certificate_authority_key_identifier :str = field(default_factory=str)
    certificate_extensions :list = field(default_factory=list)
    certificate_is_self_signed :bool = field(default_factory=bool)
    certificate_client_authentication :bool = field(default_factory=bool)
    tlsext_basic_constraints_path_length :int = field(default_factory=str)
    negotiated_cipher :str = field(default_factory=str)
    negotiated_protocol :str = field(default_factory=str)
    sni_support :bool = field(default_factory=bool)
    revocation_ocsp_stapling :bool = field(default_factory=bool)
    revocation_ocsp_must_staple :bool = field(default_factory=bool)
    port :int = 443

def filter_valid_files_urls(inputs :list[str], exception :Exception = None, tmp_path_prefix :str = '/tmp') -> list[str]:
    ret = set()
    for test in inputs:
        if test is None:
            raise exception
        file_path = Path(test)
        if file_path.is_file() is False and validators.url(test) is not True:
            raise exception
        if file_path.is_file():
            ret.add(test)
            continue
        if validators.url(test) is True:
            r = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
            local_path = f'{tmp_path_prefix}/tlsverify-{r}'
            urlretrieve(test, local_path)
            file_path = Path(local_path)
            if not file_path.is_file():
                raise exception
            ret.add(local_path)
    return list(ret)

def convert_decimal_to_serial_bytes(decimal :int):
    # add leading 0
    a = "0%x" % decimal
    # force even num bytes, remove leading 0 if necessary
    b = a[1:] if len(a)%2==1 else a
    return format(':'.join(s.encode('utf8').hex().lower() for s in b))

def get_server_expected_client_subjects(host :str, port :int = 443, cafiles :list = None) -> list[X509Name]:
    if not isinstance(port, int):
        raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
    if not isinstance(cafiles, list) and cafiles is not None:
        raise TypeError(f"provided an invalid type {type(cafiles)} for cafiles, expected list")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    logger.info('Negotiating with the server to derive expected client certificate subjects')
    expected_subjects = []
    ctx = SSL.Context(method=SSL.SSLv23_METHOD)
    ctx.load_verify_locations(cafile=where())
    for cafile in cafiles or []:
        ctx.load_verify_locations(cafile=cafile)
    ctx.verify_mode = SSL.VERIFY_NONE
    ctx.check_hostname = False
    conn = SSL.Connection(ctx, socket(AF_INET, SOCK_STREAM))
    conn.connect((host, port))
    conn.settimeout(3)
    conn.set_tlsext_host_name(idna.encode(host))
    conn.setblocking(1)
    conn.set_connect_state()
    try:
        conn.do_handshake()
        expected_subjects :list[X509Name] = conn.get_client_ca_list()
    except SSL.Error as err:
        if 'no protocols available' not in str(err) and 'alert protocol' not in str(err):
            logger.warning(err, exc_info=True)
    except Exception as ex:
        logger.warning(ex, exc_info=True)
    finally:
        conn.close()
    return expected_subjects

def get_certificates(host :str, port :int = 443, cafiles :list = None, client_pem :str = None, client_ca :str = None, tlsext :bool = False, tmp_path_prefix :str = '/tmp') -> tuple[bytes,list,Metadata]:
    if not isinstance(port, int):
        raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    if not isinstance(tmp_path_prefix, str):
        raise TypeError(f"provided an invalid type {type(tmp_path_prefix)} for tmp_path_prefix, expected str")

    client_pem_err = AttributeError(f'client_pem was provided "{client_pem}" but is not a valid URL or file does not exist')
    if client_pem is not None:
        if not isinstance(client_pem, str):
            raise client_pem_err
        res = filter_valid_files_urls([client_pem], client_pem_err, tmp_path_prefix)
        if len(res) == 1:
            client_pem = res[0]
    client_ca_err = AttributeError(f'client_ca was provided "{client_ca}" but is not a valid URL or file does not exist')
    if client_ca is not None:
        if not isinstance(client_ca, str):
            raise client_ca_err
        res = filter_valid_files_urls([client_ca], client_ca_err, tmp_path_prefix)
        if len(res) == 1:
            client_ca = res[0]

    cafiles_err = AttributeError(f'cafiles was provided but is not a valid URLs or files do not exist\n{cafiles}')
    if cafiles is not None:
        if not isinstance(cafiles, list):
            raise cafiles_err
        cafiles = filter_valid_files_urls(cafiles, cafiles_err, tmp_path_prefix)

    negotiated_cipher = None
    negotiated_protocol = None
    x509 = None
    certificate_chain = []
    verifier_errors = []
    def verifier(conn :SSL.Connection, server_cert :X509, errno :int, depth :int, preverify_ok :int):
        # preverify_ok indicates, whether the verification of the server certificate in question was passed (preverify_ok=1) or not (preverify_ok=0)
        # https://www.openssl.org/docs/man1.0.2/man1/verify.html
        verifier_errors = conn.get_app_data()
        if not isinstance(verifier_errors, list):
            verifier_errors = []
        if errno in exceptions.X509_MESSAGES.keys():
            verifier_errors.append((server_cert, exceptions.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT))
        conn.set_app_data(verifier_errors)
        return True

    for version in [SSL.SSL3_VERSION, SSL.TLS1_VERSION, SSL.TLS1_1_VERSION, SSL.TLS1_2_VERSION, SSL.TLS1_3_VERSION]:
        logger.info(f'Trying protocol {OPENSSL_VERSION_LOOKUP[version]}')
        certificate_chain = []
        ctx = SSL.Context(method=SSL.SSLv23_METHOD)
        ctx.load_verify_locations(cafile=where())
        for cafile in cafiles or []:
            ctx.load_verify_locations(cafile=cafile)
        if client_pem is not None:
            ctx.use_certificate_file(certfile=client_pem, filetype=FILETYPE_PEM)
            if client_ca is not None:
                ctx.load_client_ca(cafile=client_ca)
        """
        VERIFY_NONE: if used, no others may. if not using an anonymous cipher (by default disabled), the server will send a certificate which will be checked. The result of the certificate verification process can be checked after the TLS/SSL handshake using the SSL_get_verify_result(3) function. The handshake will be continued regardless of the verification result.
        VERIFY_PEER: ensure `ctx.set_verify` is used. the server certificate is verified. If the verification process fails, the TLS/SSL handshake is immediately terminated with an alert message containing the reason for the verification failure. If no server certificate is sent, because an anonymous cipher is used, SSL_VERIFY_PEER is ignored.
        VERIFY_FAIL_IF_NO_PEER_CERT: ignored
        VERIFY_CLIENT_ONCE: ignored
        VERIFY_POST_HANDSHAKE: ignored
        """
        ctx.set_verify(SSL.VERIFY_NONE, verifier)
        ctx.set_max_proto_version(version)
        ctx.check_hostname = False
        conn = SSL.Connection(ctx, socket(AF_INET, SOCK_STREAM))
        conn.connect((host, port))
        conn.settimeout(3)
        if tlsext is True:
            logger.info('using SNI')
            conn.set_tlsext_host_name(idna.encode(host))
        conn.setblocking(1)
        conn.set_connect_state()
        try:
            conn.do_handshake()
            verifier_errors = conn.get_app_data()
            x509 = conn.get_peer_certificate()
            negotiated_cipher = conn.get_cipher_name()
            negotiated_protocol = conn.get_protocol_version_name()
            for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                certificate_chain.append(cert)
            logger.debug(f'Peer cert chain length: {len(certificate_chain)}')
        except SSL.Error as err:
            if 'no protocols available' not in str(err) and 'alert protocol' not in str(err):
                logger.warning(err, exc_info=True)
        except Exception as ex:
            logger.warning(ex, exc_info=True)
        finally:
            conn.close()
        if x509 is not None:
            logger.debug(f'negotiated protocol {negotiated_protocol} cipher {negotiated_cipher}')
            break

    return x509, certificate_chain, negotiated_protocol, negotiated_cipher, verifier_errors

def is_self_signed(cert :Certificate) -> bool:
    certificate_is_self_signed = False
    authority_key_identifier = None
    subject_key_identifier = None
    try:
        authority_key_identifier = hexlify(cert.extensions.get_extension_for_class(extensions.AuthorityKeyIdentifier).value.key_identifier).decode('utf-8')
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
        certificate_is_self_signed = True
    try:
        subject_key_identifier = hexlify(cert.extensions.get_extension_for_class(extensions.SubjectKeyIdentifier).value.digest).decode('utf-8')
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
        certificate_is_self_signed = True
    if subject_key_identifier == authority_key_identifier:
        certificate_is_self_signed = True
    return certificate_is_self_signed

def get_san(cert :Certificate) -> list:
    san = []
    try:
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value.get_values_for_type(DNSName)
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    return san

def get_basic_constraints(cert :Certificate) -> tuple[bool, int]:
    basic_constraints = None
    try:
        basic_constraints = cert.extensions.get_extension_for_class(extensions.BasicConstraints).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    if not isinstance(basic_constraints, extensions.BasicConstraints):
        return None, None
    return basic_constraints.ca, basic_constraints.path_length

def key_usage_exists(cert :Certificate, key :str) -> bool:
    key_usage = None
    ext_key_usage = None
    try:
        key_usage = cert.extensions.get_extension_for_class(extensions.KeyUsage).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    try:
        ext_key_usage = cert.extensions.get_extension_for_class(extensions.ExtendedKeyUsage).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    if key_usage is None and ext_key_usage is None:
        logger.warning('no key usages could not be found')
        return False
    if isinstance(key_usage, extensions.KeyUsage) and hasattr(key_usage, key) and getattr(key_usage, key) is True:
        return True
    if isinstance(ext_key_usage, extensions.ExtendedKeyUsage) and key in [usage._name for usage in ext_key_usage if hasattr(usage, '_name')]:
        return True
    return False

def gather_key_usages(cert :Certificate) -> tuple[list, list, list]:
    certificate_extensions = []
    validator_key_usage = []
    validator_extended_key_usage = []
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
            if 'serverAuth' in data[data['name']]:
                validator_extended_key_usage.append('server_auth')
        if isinstance(ext.value, extensions.TLSFeature):
            data[data['name']] = []
            for feature in ext.value:
                if feature.value == 5:
                    data[data['name']].append('OCSP Must-Staple (rfc6066)')
                    validator_extended_key_usage.append('ocsp_signing')
                if feature.value == 17:
                    data[data['name']].append('multiple OCSP responses (rfc6961)')
                    validator_extended_key_usage.append('ocsp_signing')
        if isinstance(ext.value, extensions.InhibitAnyPolicy):
            data[data['name']] = ext.value.skip_certs
        if isinstance(ext.value, extensions.KeyUsage):
            data[data['name']] = []
            data['digital_signature'] = ext.value.digital_signature
            if ext.value.digital_signature:
                data[data['name']].append('digital_signature')
                validator_key_usage.append('digital_signature')
            data['content_commitment'] = ext.value.content_commitment
            if ext.value.content_commitment:
                data[data['name']].append('content_commitment')
                validator_key_usage.append('content_commitment')
            data['key_encipherment'] = ext.value.key_encipherment
            if ext.value.key_encipherment:
                data[data['name']].append('key_encipherment')
                validator_key_usage.append('key_encipherment')
            data['data_encipherment'] = ext.value.data_encipherment
            if ext.value.data_encipherment:
                data[data['name']].append('data_encipherment')
                validator_key_usage.append('data_encipherment')
            data['key_agreement'] = ext.value.key_agreement
            if ext.value.key_agreement:
                data[data['name']].append('key_agreement')
                validator_key_usage.append('key_agreement')
                data['decipher_only'] = ext.value.decipher_only
                if ext.value.decipher_only:
                    data[data['name']].append('decipher_only')
                    validator_key_usage.append('decipher_only')
                data['encipher_only'] = ext.value.encipher_only
                if ext.value.encipher_only:
                    data[data['name']].append('encipher_only')
                    validator_key_usage.append('encipher_only')
            data['key_cert_sign'] = ext.value.key_cert_sign
            if ext.value.key_cert_sign:
                data[data['name']].append('key_cert_sign')
                validator_key_usage.append('key_cert_sign')
            data['crl_sign'] = ext.value.crl_sign
            if ext.value.crl_sign:
                data[data['name']].append('crl_sign')
                validator_key_usage.append('crl_sign')
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
    return certificate_extensions, validator_key_usage, validator_extended_key_usage

def extract_certificate_common_name(cert :Certificate):
    for fields in cert.subject:
        current = str(fields.oid)
        if "commonName" in current:
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
        logger.debug(ex, exc_info=True)
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
    return delimiter.join([input[i:i+n] for i in range(0, len(input), n)])

def convert_x509_to_PEM(certificate_chain :list) -> list[bytes]:
    pem_certs = []
    for cert in certificate_chain:
        if not isinstance(cert, X509):
            raise AttributeError(f'convert_x509_to_PEM expected OpenSSL.crypto.X509, got {type(cert)}')
        pem_certs.append(dump_certificate(FILETYPE_PEM, cert))
    return pem_certs
