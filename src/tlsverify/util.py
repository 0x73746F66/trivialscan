import logging
import string
import random
from io import BytesIO
from datetime import datetime, timedelta
from urllib.request import urlretrieve
from urllib.parse import urlparse
from binascii import hexlify
from pathlib import Path
import requests
import validators
from cryptography import x509
from cryptography.x509 import Certificate, extensions, SubjectAlternativeName, DNSName
from OpenSSL import SSL
from OpenSSL.crypto import X509, FILETYPE_PEM, dump_certificate
from retry.api import retry
from certvalidator import CertificateValidator, ValidationContext
from rich.style import Style
from rich.console import Console
from dns import resolver, dnssec, rdatatype, message, query, name as dns_name
from dns.exception import DNSException, Timeout as DNSTimeoutError
from dns.resolver import NoAnswer
from tldextract import TLDExtract
from . import constants

__module__ = 'tlsverify.util'

logger = logging.getLogger(__name__)

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
    return [
        ext.value
        for ext in cert.extensions
        if not isinstance(ext.value, extensions.UnrecognizedExtension)
    ]

def get_extensions_by_oid(cert :Certificate, oid :str) -> extensions.Extension:
    for ext in cert.extensions:
        if ext.oid._dotted_string == oid:
            return ext
    return None

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
            data['authority_cert_issuer'] = ', '.join(str(x.value) for x in ext.value.authority_cert_issuer or [])
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
        if isinstance(ext, extensions.ExtendedKeyUsage):
            extended_usages = [x._name for x in ext or []] # pylint: disable=protected-access
            if 'serverAuth' in extended_usages:
                validator_extended_key_usage.append('server_auth')
        if isinstance(ext, extensions.TLSFeature):
            for feature in ext:
                if feature.value in [5, 17]:
                    validator_extended_key_usage.append('ocsp_signing')
        if isinstance(ext, extensions.KeyUsage):
            validator_key_usage += _extract_key_usage(ext)
    return validator_key_usage, validator_extended_key_usage

def _extract_key_usage(ext):
    validator_key_usage = []
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
    return validator_key_usage

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

def issuer_from_chain(certificate :X509, chain :list[X509]) -> Certificate:
    issuer = None
    issuer_name = certificate.get_issuer().CN
    if issuer_name:
        for peer in chain:
            peer_name = peer.get_subject().CN
            if not peer_name:
                continue
            if peer_name.strip() == issuer_name.strip():
                issuer = peer
                break
    return issuer

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
        return "Expired yesterday"
    if interval.days == 0:
        return "Expires today"
    if interval.days == 1:
        return "Expires tomorrow"
    if interval.days > 365:
        return f"Expires in {interval.days} days ({int(round(interval.days/365))} years)"
    if interval.days > 1:
        return f"Expires in {interval.days} days"

def styled_boolean(value :bool, represent_as :tuple[str, str] = ('True', 'False'), colors :tuple[str, str] = ('dark_sea_green2', 'light_coral')) -> str:
    console = Console()
    if not isinstance(value, bool):
        raise TypeError(f'{type(value)} provided')
    val = represent_as[0] if value else represent_as[1]
    color = colors[0] if value else colors[1]
    with console.capture() as capture:
        console.print(val, style=Style(color=color))
    return capture.get().strip()

def styled_value(value :str, color :str = 'white') -> str:
    if value.startswith("http"):
        return value
    if len(value) > 70:
        return value
    console = Console()
    with console.capture() as capture:
        console.print(value, style=Style(color=color), no_wrap=True)
    return capture.get().strip()

def styled_list(values :list, delimiter :str = '\n', color :str = 'bright_white') -> str:
    styled_values = []
    for value in values:
        if value is None:
            styled_values.append(styled_value('Unknown', 'cornflower_blue'))
            continue
        if isinstance(value, bool):
            styled_values.append(styled_boolean(value, colors=(color, color)))
            continue
        if isinstance(value, list):
            styled_values.append(styled_list(value, delimiter, color))
            continue
        if isinstance(value, dict):
            styled_values.append(styled_dict(value, delimiter, colors=(color, color)))
            continue
        if isinstance(value, bytes):
            value = value.decode()
        if isinstance(value, datetime):
            value = value.isoformat()
        styled_values.append(styled_value(str(value), color=color))

    return delimiter.join(styled_values)

def styled_dict(values :dict, delimiter :str = '=', colors :tuple[str, str] = ('bright_white', 'bright_white')) -> str:
    pairs = []
    for key, v in values.items():
        if isinstance(v, bool):
            pairs.append(f'{key}{delimiter}{styled_boolean(v)}')
            continue
        if v is None:
            pairs.append(f'{key}{delimiter}{styled_value("null", color=colors[1])}')
            continue
        if isinstance(v, list):
            pairs.append(f'{key}{delimiter}{styled_list(v, color=colors[1])}')
            continue
        if isinstance(v, dict):
            pairs.append(f'{key}{delimiter}{styled_dict(v, delimiter=delimiter, colors=colors)}')
            continue
        if isinstance(v, (int, float)):
            v = str(v)
        if isinstance(v, bytes):
            v = v.decode()
        if isinstance(v, datetime):
            v = v.isoformat()
        if isinstance(v, str):
            pairs.append(f'{key}{delimiter}{styled_value(v, color=colors[1])}')
    return '\n'.join(pairs)

def styled_any(value, dict_delimiter='=', list_delimiter='\n', color :str = 'bright_white') -> str:
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if isinstance(value, (str, int)):
        return str(value)
    if value is None:
        return styled_value('None', color=color)
    if isinstance(value, bool):
        return styled_boolean(value)
    if isinstance(value, dict):
        return styled_dict(value, delimiter=dict_delimiter)
    if isinstance(value, list):
        return styled_list(value, delimiter=list_delimiter, color=color)
    if isinstance(value, bytes):
        return styled_value(value.decode(), color=color)
    if isinstance(value, datetime):
        return styled_value(value.isoformat(), color=color)
    return styled_value(value, color=color)

def get_dnssec(domain_name :str):
    logger.warning(DeprecationWarning('util.get_dnssec() was deprecated in version 0.4.3 and will be removed in version 0.5.0'), exc_info=True)
    return get_dnssec_answer(domain_name)

def get_txt_answer(domain_name :str) -> resolver.Answer:
    logger.info(f'Trying to resolve TXT for {domain_name}')
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    try:
        response = resolver.query(domain_name, rdatatype.TXT)
    except NoAnswer:
        logger.warning('DNS NoAnswer')
        return None
    except DNSTimeoutError:
        logger.warning('DNS Timeout')
        return None
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
        return None
    except ConnectionResetError:
        logger.warning('Connection reset by peer')
        return None
    except ConnectionError:
        logger.warning('Name or service not known')
        return None
    logger.info(f'answered {response.answer}')
    return response.answer

def get_tlsa_answer(domain_name :str) -> resolver.Answer:
    logger.info(f'Trying to resolve TLSA for {domain_name}')
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    try:
        response = resolver.query(domain_name, rdatatype.TLSA)
    except NoAnswer:
        logger.warning('DNS NoAnswer')
        return None
    except DNSTimeoutError:
        logger.warning('DNS Timeout')
        return None
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
        return None
    except ConnectionResetError:
        logger.warning('Connection reset by peer')
        return None
    except ConnectionError:
        logger.warning('Name or service not known')
        return None
    logger.info(f'answered {response.answer}')
    return response.answer

def get_dnssec_answer(domain_name :str):
    logger.info(f'Trying to resolve DNSSEC for {domain_name}')
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    tldext = TLDExtract(cache_dir='/tmp')(f'http://{domain_name}')
    answers = []
    try:
        response = resolver.query(domain_name, rdatatype.NS)
    except NoAnswer:
        return get_dnssec_answer(tldext.registered_domain) if tldext.registered_domain != domain_name else None
    except DNSTimeoutError:
        logger.warning('DNS Timeout')
        return None
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
        return None
    except ConnectionResetError:
        logger.warning('Connection reset by peer')
        return None
    except ConnectionError:
        logger.warning('Name or service not known')
        return None
    dns_resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
    nameservers = []
    for ns in [i.to_text() for i in response.rrset]:
        logger.info(f'Checking A for {ns}')
        try:
            response = dns_resolver.query(ns, rdtype=rdatatype.A)
        except DNSTimeoutError:
            logger.warning(f'DNS Timeout {ns} A')
            continue
        except DNSException as ex:
            logger.warning(ex, exc_info=True)
            continue
        except ConnectionResetError:
            logger.warning(f'Connection reset by peer {ns} A')
            continue
        except ConnectionError:
            logger.warning(f'Name or service not known {ns} A')
            continue
        nameservers += [i.to_text() for i in response.rrset]
    if not nameservers:
        logger.warning('No nameservers found')
        return None
    for ns in nameservers:
        logger.info(f'Trying to resolve DNSKEY using NS {ns}')
        try:
            request = message.make_query(domain_name, rdatatype.DNSKEY, want_dnssec=True)
            response = query.udp(request, ns, timeout=2)
        except DNSTimeoutError:
            logger.warning('DNSKEY DNS Timeout')
            continue
        except DNSException as ex:
            logger.warning(ex, exc_info=True)
            continue
        except ConnectionResetError:
            logger.warning('DNSKEY Connection reset by peer')
            continue
        except ConnectionError:
            logger.warning('DNSKEY Name or service not known')
            continue
        if response.rcode() != 0:
            logger.warning('No DNSKEY record')
            continue

        logger.info(f'{ns} answered {response.answer}')
        if len(response.answer) == 2:
            return response.answer
        answers += response.answer
        if len(answers) == 2:
            return answers

    return get_dnssec_answer(tldext.registered_domain) if tldext.registered_domain != domain_name else None

def dnssec_valid(domain_name) -> bool:
    answer = get_dnssec_answer(domain_name)
    if answer is None:
        return False
    if len(answer) != 2:
        logger.warning(f'DNSKEY answer too many values {len(answer)}')
        return False
    name = dns_name.from_text(domain_name)
    try:
        dnssec.validate(answer[0], answer[1], {name: answer[0]})
    except dnssec.ValidationFailure as err:
        logger.warning(err, exc_info=True)
        return False
    except AttributeError as err:
        logger.warning(err, exc_info=True)
        return False
    return True

def get_caa(domain_name :str):
    tldext = TLDExtract(cache_dir='/tmp')(f'http://{domain_name}')
    try_apex = tldext.registered_domain != domain_name
    response = None
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    try:
        response = resolver.query(domain_name, rdatatype.CAA)
    except DNSTimeoutError:
        logger.warning('DNS Timeout')
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
    except ConnectionResetError:
        logger.warning('Connection reset by peer')
    except ConnectionError:
        logger.warning('Name or service not known')
    if not response and try_apex:
        logger.info(f'Trying to resolve CAA for {tldext.registered_domain}')
        return get_caa(tldext.registered_domain)
    if not response:
        return None
    return response

def caa_exist(domain_name :str) -> bool:
    logger.info(f'Trying to resolve CAA for {domain_name}')
    response = get_caa(domain_name)
    if response is None:
        logger.info('No CAA records')
        return False
    issuers = set()
    for rdata in response:
        common_name, *rest = rdata.value.decode().split(';')
        issuers.add(common_name.strip())

    return len(issuers) > 0

def caa_valid(domain_name :str, cert :X509, certificate_chain :list[X509]) -> bool:
    extractor = TLDExtract(cache_dir='/tmp')
    response = get_caa(domain_name)
    if response is None:
        return False
    wild_issuers = set()
    issuers = set()
    for rdata in response:
        caa, *_ = rdata.value.decode().split(';')
        if 'issuewild' in rdata.to_text():
            wild_issuers.add(caa.strip())
    for rdata in response:
        caa, *_ = rdata.value.decode().split(';')
        # issuewild tags take precedence over issue tags when specified.
        if caa not in wild_issuers:
            issuers.add(caa.strip())

    issuer = issuer_from_chain(cert, certificate_chain)
    if not isinstance(issuer, X509):
        logger.warning('Issuer certificate not found in chain')
        return False
    
    common_name = cert.get_subject().CN
    if not common_name:
        return False
    issuer_cn = issuer.get_subject().O
    for caa in wild_issuers:
        issuer_common_names :list[str] = constants.CAA_DOMAINS.get(caa, [])
        if not issuer_common_names:
            issuer_ext = extractor(f'http://{caa}')
            issuer_apex = issuer_ext.registered_domain
            issuer_common_names = constants.CAA_DOMAINS.get(issuer_apex, [])
        if issuer_cn in issuer_common_names:
            return True

    if common_name.startswith('*.'):
        return False

    for caa in issuers:
        issuer_common_names :list[str] = constants.CAA_DOMAINS.get(caa, [])
        if not issuer_common_names:
            issuer_ext = extractor(f'http://{caa}')
            issuer_apex = issuer_ext.registered_domain
            issuer_common_names = constants.CAA_DOMAINS.get(issuer_apex, [])
        if issuer_cn in issuer_common_names:
            return True

    return False

def crlite_revoked(db_path :str, pem :bytes, use_sqlite :bool = True):
    if use_sqlite:
        from crlite_query import IntermediatesDB
    else:
        import sqlite3
        sqlite3.sqlite_version_info = (3, 37, 2)
        class IntermediatesDB(object):
            def __init__(self, *, db_path, download_pems=False):
                pass
            def __len__(self):
                return 0
            def __str__(self):
                return f"{len(self)} Intermediates"
            def update(self, *, collection_url, attachments_base_url):
                pass
            def issuer_by_DN(self, distinguishedName):
                return None
    from crlite_query import CRLiteDB, CRLiteQuery

    def find_attachments_base_url():
        url = urlparse(constants.CRLITE_URL)
        base_rsp = requests.get(f"{url.scheme}://{url.netloc}/v1/")
        return base_rsp.json()["capabilities"]["attachments"]["base_url"]

    db_dir = Path(db_path)
    if not db_dir.is_dir():
        db_dir.mkdir()

    last_updated = None
    last_updated_file = (db_dir / ".last_updated")
    if last_updated_file.is_file():
        last_updated = datetime.fromtimestamp(last_updated_file.stat().st_mtime)
    grace_time = datetime.utcnow() - timedelta(hours=6)
    update = True
    if last_updated is not None and last_updated > grace_time:
        logger.info(f"Database was updated at {last_updated}, skipping.")
        update = False
    crlite_db = CRLiteDB(db_path=db_path)
    if update:
        crlite_db.update(
            collection_url=constants.CRLITE_URL,
            attachments_base_url=find_attachments_base_url(),
        )
        crlite_db.cleanup()
        last_updated_file.touch()
        logger.info(f"Status: {crlite_db}")

    query = CRLiteQuery(crlite_db=crlite_db, intermediates_db=IntermediatesDB(db_path=db_path, download_pems=False))
    results = []
    for result in query.query(name='peer', generator=query.gen_from_pem(BytesIO(pem))):
        logger.info(result.print_query_result(verbose=1))
        logger.debug(result.print_query_result(verbose=3))
        results.append(result.is_revoked())
    return any(results)


@retry(SSL.WantReadError, tries=5, delay=.5)
def do_handshake(conn):
    try:
        conn.do_handshake()
    except SSL.SysCallError:
        pass
