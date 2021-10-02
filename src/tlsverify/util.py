from dataclasses import dataclass, field
from binascii import hexlify
from ssl import create_default_context, SSLCertVerificationError, Purpose
from socket import socket, AF_INET, SOCK_STREAM
from cryptography import x509
from cryptography.x509 import Certificate, extensions
from OpenSSL import SSL
from certvalidator import CertificateValidator, ValidationContext
import validators
import idna
from tlsverify.exceptions import ValidationError

__module__ = 'tlsverify.util'

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

@dataclass
class Metadata:
    host :str
    certificate_public_key_type :str = field(default_factory=str)
    certificate_key_size :int = field(default_factory=int)
    certificate_serial_number :str = field(default_factory=str)
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
    certificate_extensions :list = field(default_factory=list)
    certificate_is_self_signed : bool = field(default_factory=bool)
    negotiated_cipher :str = field(default_factory=str)
    negotiated_protocol :str = field(default_factory=str)
    revocation_ocsp_stapling :bool = field(default_factory=bool)
    revocation_ocsp_must_staple :bool = field(default_factory=bool)
    port :int = 443

def get_certificates(host :str, port :int = 443, cafiles :list = None, tlsext :bool = False) -> tuple[bytes,list,Metadata]:
    if cafiles is not None and not isinstance(cafiles, list):
        raise TypeError(f"provided an invalid type {type(cafiles)} for cafiles, expected list")
    if not isinstance(port, int):
        raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")

    x509 = None
    certificate_chain = []
    metadata = Metadata(host=host, port=port)
    for method in [SSL.TLSv1_METHOD, SSL.TLSv1_1_METHOD, SSL.TLSv1_2_METHOD, SSL.SSLv23_METHOD]:
        certificate_chain = []
        ctx = SSL.Context(method=method)
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE
        conn = SSL.Connection(ctx, socket(AF_INET, SOCK_STREAM))
        conn.connect((host, port))
        conn.settimeout(3)
        if tlsext is True:
            conn.set_tlsext_host_name(idna.encode(host))
        conn.setblocking(1)
        try:
            conn.do_handshake()
            x509 = conn.get_peer_certificate()
            for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                certificate_chain.append(cert)
            metadata.negotiated_cipher = conn.get_cipher_name()
            metadata.negotiated_protocol = conn.get_protocol_version_name()
        finally:
            conn.close()
        if x509 is not None:
            break
    return x509, certificate_chain, metadata

def is_self_signed(cert :Certificate) -> bool:
    certificate_is_self_signed = False
    authority_key_identifier = None
    subject_key_identifier = None
    try:
        authority_key_identifier = hexlify(cert.extensions.get_extension_for_class(extensions.AuthorityKeyIdentifier).value.key_identifier).decode('utf-8')
    except extensions.ExtensionNotFound:
        certificate_is_self_signed = True
    try:
        subject_key_identifier = hexlify(cert.extensions.get_extension_for_class(extensions.SubjectKeyIdentifier).value.key_identifier).decode('utf-8')
    except extensions.ExtensionNotFound:
        certificate_is_self_signed = True
    if subject_key_identifier == authority_key_identifier:
        certificate_is_self_signed = True
    return certificate_is_self_signed

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
    except extensions.ExtensionNotFound:
        pass
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
    validator.validate_usage(
        key_usage=set(validator_key_usage),
        extended_key_usage=set(validator_extended_key_usage),
    )
