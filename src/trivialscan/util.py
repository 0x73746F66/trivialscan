import logging
import string
import random
import signal
import json
import hmac
import hashlib
from base64 import b64encode
from datetime import datetime, date, time
from urllib.request import urlretrieve
from urllib.parse import urlparse
from binascii import hexlify
from pathlib import Path
from decimal import Decimal
from functools import wraps
from typing import Union, Any
from copy import deepcopy
from io import BytesIO
from os import path

import requests
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
from rich.progress import (
    Task,
    Progress,
    DownloadColumn,
    BarColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
import validators
from cryptography import x509
from cryptography.x509 import (
    Certificate,
    extensions,
    SubjectAlternativeName,
    DNSName,
    Name,
)
from OpenSSL import SSL
from OpenSSL.crypto import X509, FILETYPE_PEM, dump_certificate
from retry.api import retry
from bs4 import BeautifulSoup as bs
from asn1crypto.x509 import Certificate as asn1Certificate
from certvalidator import CertificateValidator, ValidationContext
from dns import resolver, dnssec, rdatatype, message, query, name as dns_name
from dns.exception import DNSException, Timeout as DNSTimeoutError
from dns.resolver import NoAnswer
from tldextract import TLDExtract
from tlstrust import util as tlstrust_util
from tlstrust.context import STORES

from . import constants, models
from .certificate import (
    BaseCertificate,
    RootCertificate,
    IntermediateCertificate,
    LeafCertificate,
)

__module__ = "trivialscan.util"

logger = logging.getLogger(__name__)
MAX_DEPTH = 8


def timeout(seconds, error_message="Function call timed out"):
    def decorated(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorated


def force_str(s, encoding="utf-8", strings_only=False, errors="strict"):
    if issubclass(type(s), str):
        return s
    if strings_only and isinstance(
        s,
        (
            type(None),
            int,
            float,
            Decimal,
            datetime,
            date,
            time,
        ),
    ):
        return s
    if isinstance(s, bytes):
        s = str(s, encoding, errors)
    else:
        s = str(s)
    return s


def filter_valid_files_urls(inputs: list[str], tmp_path_prefix: str = "/tmp"):
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
            r = "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(16)
            )
            local_path = f"{tmp_path_prefix}/trivialscan-{r}"
            try:
                urlretrieve(test, local_path)
            except Exception as ex:
                logger.error(ex, exc_info=True)
            file_path = Path(local_path)
            if not file_path.is_file():
                return False
            ret.add(local_path)
    return list(ret)


def convert_decimal_to_serial_bytes(decimal: int):
    # add leading 0
    a = "0%x" % decimal
    # force even num bytes, remove leading 0 if necessary
    b = a[1:] if len(a) % 2 == 1 else a
    return format(":".join(s.encode("utf8").hex().lower() for s in b))


def is_self_signed(cert: Certificate) -> bool:
    certificate_is_self_signed = False
    authority_key_identifier = None
    subject_key_identifier = None
    try:
        authority_key_identifier = hexlify(
            cert.extensions.get_extension_for_class(
                extensions.AuthorityKeyIdentifier
            ).value.key_identifier
        ).decode("utf-8")
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
        certificate_is_self_signed = True
    try:
        subject_key_identifier = hexlify(
            cert.extensions.get_extension_for_class(
                extensions.SubjectKeyIdentifier
            ).value.digest
        ).decode("utf-8")
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
        certificate_is_self_signed = True
    if subject_key_identifier == authority_key_identifier:
        certificate_is_self_signed = True
    return certificate_is_self_signed


def get_san(cert: Certificate) -> list:
    san = []
    try:
        san = cert.extensions.get_extension_for_class(
            SubjectAlternativeName
        ).value.get_values_for_type(DNSName)
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    return sorted(san)


def get_basic_constraints(cert: Certificate) -> tuple[bool, int]:
    basic_constraints = None
    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            extensions.BasicConstraints
        ).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    if not isinstance(basic_constraints, extensions.BasicConstraints):
        return None, None
    return basic_constraints.ca, basic_constraints.path_length


def key_usage_exists(cert: Certificate, key: str) -> bool:
    key_usage = None
    ext_key_usage = None
    try:
        key_usage = cert.extensions.get_extension_for_class(extensions.KeyUsage).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    try:
        ext_key_usage = cert.extensions.get_extension_for_class(
            extensions.ExtendedKeyUsage
        ).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    if key_usage is None and ext_key_usage is None:
        logger.warning("no key usages could not be found")
        return False
    if (
        isinstance(key_usage, extensions.KeyUsage)
        and hasattr(key_usage, key)
        and getattr(key_usage, key) is True
    ):
        return True
    if isinstance(ext_key_usage, extensions.ExtendedKeyUsage) and key in [
        usage._name for usage in ext_key_usage if hasattr(usage, "_name")
    ]:
        return True
    return False


def get_valid_certificate_extensions(cert: Certificate) -> list[extensions.Extension]:
    return [
        ext.value
        for ext in cert.extensions
        if not isinstance(ext.value, extensions.UnrecognizedExtension)
    ]


def get_extensions_by_oid(cert: Certificate, oid: str) -> extensions.Extension:
    for ext in cert.extensions:
        if ext.oid._dotted_string == oid:
            return ext
    return None


def get_certificate_extensions(cert: Certificate) -> list[dict]:
    certificate_extensions = []
    for ext in cert.extensions:
        data = {
            "critical": ext.critical,
            "name": ext.oid._name,  # pylint: disable=protected-access
        }
        if isinstance(ext.value, extensions.UnrecognizedExtension):
            data = {**data, **vars(ext.value)}
        if isinstance(ext.value, extensions.CRLNumber):
            data[data["name"]] = ext.value.crl_number
        if isinstance(ext.value, extensions.AuthorityKeyIdentifier):
            data[data["name"]] = hexlify(ext.value.key_identifier).decode("utf-8")
            data["authority_cert_issuer"] = ", ".join(
                str(x.value) for x in ext.value.authority_cert_issuer or []
            )
            data[
                "authority_cert_serial_number"
            ] = ext.value.authority_cert_serial_number
        if isinstance(ext.value, extensions.SubjectKeyIdentifier):
            data[data["name"]] = hexlify(ext.value.digest).decode("utf-8")
        if isinstance(
            ext.value,
            (
                extensions.AuthorityInformationAccess,
                extensions.SubjectInformationAccess,
            ),
        ):
            data[data["name"]] = []
            for description in ext.value:
                data[data["name"]].append(
                    {
                        "access_location": description.access_location.value,
                        "access_method": description.access_method._name,  # pylint: disable=protected-access
                    }
                )
        if isinstance(ext.value, extensions.BasicConstraints):
            data["ca"] = ext.value.ca
            data["path_length"] = ext.value.path_length
        if isinstance(ext.value, extensions.DeltaCRLIndicator):
            data[data["name"]] = ext.value.crl_number
        if isinstance(
            ext.value, (extensions.CRLDistributionPoints, extensions.FreshestCRL)
        ):
            data[data["name"]] = []
            for distribution_point in ext.value:
                data[data["name"]].append(
                    {
                        "full_name": ", ".join(
                            [x.value for x in distribution_point.full_name or []]
                        ),
                        "relative_name": distribution_point.relative_name,
                        "reasons": distribution_point.reasons,
                        "crl_issuer": ", ".join(
                            [x.value for x in distribution_point.crl_issuer or []]
                        ),
                    }
                )
        if isinstance(ext.value, extensions.PolicyConstraints):
            data["policy_information"] = []
            data["user_notices"] = []
            for info in ext.value:
                if hasattr(info, "require_explicit_policy"):
                    data["policy_information"].append(
                        {
                            "require_explicit_policy": info.require_explicit_policy,
                            "inhibit_policy_mapping": info.inhibit_policy_mapping,
                        }
                    )
                if hasattr(info, "notice_reference"):
                    data["user_notices"].append(
                        {
                            "organization": info.notice_reference.organization,
                            "notice_numbers": info.notice_reference.notice_numbers,
                            "explicit_text": info.explicit_text,
                        }
                    )
        if isinstance(ext.value, extensions.ExtendedKeyUsage):
            data[data["name"]] = [
                x._name for x in ext.value or []
            ]  # pylint: disable=protected-access
        if isinstance(ext.value, extensions.TLSFeature):
            data[data["name"]] = []
            for feature in ext.value:
                if feature.value == 5:
                    data[data["name"]].append("OCSP Must-Staple (rfc6066)")
                if feature.value == 17:
                    data[data["name"]].append("multiple OCSP responses (rfc6961)")
        if isinstance(ext.value, extensions.InhibitAnyPolicy):
            data[data["name"]] = ext.value.skip_certs
        if isinstance(ext.value, extensions.KeyUsage):
            data[data["name"]] = []
            data["digital_signature"] = ext.value.digital_signature
            if ext.value.digital_signature:
                data[data["name"]].append("digital_signature")
            data["content_commitment"] = ext.value.content_commitment
            if ext.value.content_commitment:
                data[data["name"]].append("content_commitment")
            data["key_encipherment"] = ext.value.key_encipherment
            if ext.value.key_encipherment:
                data[data["name"]].append("key_encipherment")
            data["data_encipherment"] = ext.value.data_encipherment
            if ext.value.data_encipherment:
                data[data["name"]].append("data_encipherment")
            data["key_agreement"] = ext.value.key_agreement
            if ext.value.key_agreement:
                data[data["name"]].append("key_agreement")
                data["decipher_only"] = ext.value.decipher_only
                if ext.value.decipher_only:
                    data[data["name"]].append("decipher_only")
                data["encipher_only"] = ext.value.encipher_only
                if ext.value.encipher_only:
                    data[data["name"]].append("encipher_only")
            data["key_cert_sign"] = ext.value.key_cert_sign
            if ext.value.key_cert_sign:
                data[data["name"]].append("key_cert_sign")
            data["crl_sign"] = ext.value.crl_sign
            if ext.value.crl_sign:
                data[data["name"]].append("crl_sign")
        if isinstance(ext.value, extensions.NameConstraints):
            data["permitted_subtrees"] = [
                x.value for x in ext.value.permitted_subtrees or []
            ]
            data["excluded_subtrees"] = [
                x.value for x in ext.value.excluded_subtrees or []
            ]
        if isinstance(ext.value, extensions.SubjectAlternativeName):
            data[data["name"]] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.IssuerAlternativeName):
            data[data["name"]] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.CertificateIssuer):
            data[data["name"]] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.CRLReason):
            data[data["name"]] = ext.value.reason
        if isinstance(ext.value, extensions.InvalidityDate):
            data[data["name"]] = ext.value.invalidity_date
        if isinstance(
            ext.value,
            (
                extensions.PrecertificateSignedCertificateTimestamps,
                extensions.SignedCertificateTimestamps,
            ),
        ):
            data[data["name"]] = []
            for signed_cert_timestamp in ext.value:
                data[data["name"]].append(
                    {
                        "version": signed_cert_timestamp.version.name,
                        "log_id": hexlify(signed_cert_timestamp.log_id).decode("utf-8"),
                        "timestamp": signed_cert_timestamp.timestamp,
                        "pre_certificate": signed_cert_timestamp.entry_type.value == 1,
                    }
                )
        if isinstance(ext.value, extensions.OCSPNonce):
            data[data["name"]] = ext.value.nonce
        if isinstance(ext.value, extensions.IssuingDistributionPoint):
            data["full_name"] = ext.value.full_name
            data["relative_name"] = ext.value.relative_name
            data["only_contains_user_certs"] = ext.value.only_contains_user_certs
            data["only_contains_ca_certs"] = ext.value.only_contains_ca_certs
            data["only_some_reasons"] = ext.value.only_some_reasons
            data["indirect_crl"] = ext.value.indirect_crl
            data[
                "only_contains_attribute_certs"
            ] = ext.value.only_contains_attribute_certs
        certificate_extensions.append(data)
    return certificate_extensions


def gather_key_usages(cert: Certificate) -> tuple[list, list]:
    validator_key_usage = []
    validator_extended_key_usage = []
    for ext in get_valid_certificate_extensions(cert):
        if isinstance(ext, extensions.UnrecognizedExtension):
            continue
        if isinstance(ext, extensions.ExtendedKeyUsage):
            extended_usages = [
                x._name for x in ext or []
            ]  # pylint: disable=protected-access
            if "serverAuth" in extended_usages:
                validator_extended_key_usage.append("server_auth")
        if isinstance(ext, extensions.TLSFeature):
            for feature in ext:
                if feature.value in [5, 17]:
                    validator_extended_key_usage.append("ocsp_signing")
        if isinstance(ext, extensions.KeyUsage):
            validator_key_usage += _extract_key_usage(ext)
    return validator_key_usage, validator_extended_key_usage


def _extract_key_usage(ext: extensions.Extension):
    validator_key_usage = []
    if ext.digital_signature:
        validator_key_usage.append("digital_signature")
    if ext.content_commitment:
        validator_key_usage.append("content_commitment")
    if ext.key_encipherment:
        validator_key_usage.append("key_encipherment")
    if ext.data_encipherment:
        validator_key_usage.append("data_encipherment")
    if ext.key_agreement:
        validator_key_usage.append("key_agreement")
        if ext.decipher_only:
            validator_key_usage.append("decipher_only")
        if ext.encipher_only:
            validator_key_usage.append("encipher_only")
    if ext.key_cert_sign:
        validator_key_usage.append("key_cert_sign")
    if ext.crl_sign:
        validator_key_usage.append("crl_sign")
    return validator_key_usage


def get_ski_aki(cert: Certificate) -> tuple[str, str]:
    ski = None
    aki = None
    for ext in get_certificate_extensions(cert):
        if ext["name"] == "subjectKeyIdentifier":
            ski = ext[ext["name"]]
        if ext["name"] == "authorityKeyIdentifier":
            aki = ext[ext["name"]]

    return ski, aki


def extract_from_subject(
    cert: Certificate, name: str = "commonName"
) -> Union[str, None]:
    for fields in cert.subject:
        current = str(fields.oid)
        if name in current:
            return fields.value
    return None


def validate_common_name(common_name: str, host: str) -> bool:
    if not isinstance(common_name, str):
        raise ValueError("invalid certificate_common_name provided")
    if not isinstance(host, str):
        raise ValueError("invalid host provided")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    if common_name.startswith("*."):
        common_name_suffix = common_name.replace("*.", "")
        if validators.domain(common_name_suffix) is not True:
            return False
        if common_name_suffix == host:
            return True
        if not host.endswith(common_name_suffix):
            return False
        # remove suffix, only subdomain remains
        subdomain = host.replace(common_name_suffix, "").strip(".")
        return (
            "." not in subdomain
        )  # further subdomains cause Chrome NET::ERR_CERT_COMMON_NAME_INVALID
    return validators.domain(common_name) is True


def from_subject(subject: Name, field: str = "commonName") -> Union[str, None]:
    for fields in subject:
        current = str(fields.oid)
        if field in current:
            return fields.value
    return None


def match_hostname(host: str, cert: Certificate) -> bool:
    if not isinstance(host, str):
        raise ValueError("invalid host provided")
    if not isinstance(cert, Certificate):
        raise ValueError("invalid Certificate provided")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    certificate_san = []
    try:
        certificate_san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, exc_info=True)
    valid_common_name = False
    wildcard_hosts = set()
    domains = set()
    common_name = from_subject(cert.subject)
    if common_name:
        valid_common_name = validate_common_name(common_name, host)
    for san in certificate_san:
        if san.startswith("*."):
            wildcard_hosts.add(san)
        else:
            domains.add(san)
    matched_wildcard = False
    for wildcard in wildcard_hosts:
        check = wildcard.replace("*", "")
        if host.endswith(check):
            matched_wildcard = True
            break

    return valid_common_name is True and (matched_wildcard is True or host in domains)


def validate_certificate_chain(
    cert: Union[bytes, asn1Certificate],
    pem_certificate_chain: list,
    validator_key_usage: list,
    validator_extended_key_usage: list,
):
    # TODO perhaps remove certvalidator, consider once merged: https://github.com/pyca/cryptography/issues/2381
    ctx = ValidationContext(
        allow_fetching=True,
        revocation_mode="hard-fail",
        weak_hash_algos={"md2", "md5", "sha1"},
    )
    validator = CertificateValidator(
        cert, validation_context=ctx, intermediate_certs=pem_certificate_chain
    )
    return validator.validate_usage(
        key_usage=set(validator_key_usage),
        extended_key_usage=set(validator_extended_key_usage),
    )


def issuer_from_chain(certificate: X509, chain: list[X509]) -> X509:
    issuer = None
    try:
        issuer_name = certificate.get_issuer().CN
        if issuer_name:
            for peer in chain:
                peer_name = peer.get_subject().CN
                if not peer_name:
                    continue
                if peer_name.strip() == issuer_name.strip():
                    issuer = peer
                    break
    except AttributeError:
        pass
    return issuer


def str_n_split(input: str, n: int = 2, delimiter: str = " "):
    if not isinstance(input, str):
        return input
    return delimiter.join(
        [input[i : i + n] for i in range(0, len(input), n)]  # noqa: E203
    )


def convert_x509_to_PEM(certificate_chain: list) -> list[bytes]:
    pem_certs = []
    for cert in certificate_chain:
        if not isinstance(cert, X509):
            raise AttributeError(
                f"convert_x509_to_PEM expected OpenSSL.crypto.X509, got {type(cert)}"
            )
        pem_certs.append(dump_certificate(FILETYPE_PEM, cert))
    return pem_certs


def date_diff(comparer: datetime) -> str:
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
        return (
            f"Expires in {interval.days} days ({int(round(interval.days/365))} years)"
        )
    if interval.days > 1:
        return f"Expires in {interval.days} days"


def get_txt_answer(domain_name: str) -> resolver.Answer:
    logger.info(f"Trying to resolve TXT for {domain_name}")
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    try:
        response = dns_resolver.resolve(domain_name, rdatatype.TXT)
    except NoAnswer:
        logger.warning("DNS NoAnswer")
        return None
    except DNSTimeoutError:
        logger.warning("DNS Timeout")
        return None
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
        return None
    except ConnectionResetError:
        logger.warning("Connection reset by peer")
        return None
    except ConnectionError:
        logger.warning("Name or service not known")
        return None
    logger.info(f"answered {response.answer}")
    return response.answer


def get_tlsa_answer(domain_name: str) -> resolver.Answer:
    logger.info(f"Trying to resolve TLSA for {domain_name}")
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    try:
        response = dns_resolver.resolve(domain_name, rdatatype.TLSA)
    except NoAnswer:
        logger.warning("DNS NoAnswer")
        return None
    except DNSTimeoutError:
        logger.warning("DNS Timeout")
        return None
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
        return None
    except ConnectionResetError:
        logger.warning("Connection reset by peer")
        return None
    except ConnectionError:
        logger.warning("Name or service not known")
        return None
    logger.info(f"answered {response.answer}")
    return response.answer


def get_dnssec_answer(domain_name: str):
    logger.info(f"Trying to resolve DNSSEC for {domain_name}")
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    dns_resolver.lifetime = 5
    tldext = TLDExtract(cache_dir="/tmp")(f"http://{domain_name}")
    answers = []
    try:
        response = dns_resolver.resolve(domain_name, rdatatype.NS)
    except NoAnswer:
        return (
            get_dnssec_answer(tldext.registered_domain)
            if tldext.registered_domain != domain_name
            else None
        )
    except DNSTimeoutError:
        logger.warning("DNS Timeout")
        return None
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
        return None
    except ConnectionResetError:
        logger.warning("Connection reset by peer")
        return None
    except ConnectionError:
        logger.warning("Name or service not known")
        return None
    nameservers = []
    for ns in [i.to_text() for i in response.rrset]:
        logger.info(f"Checking A for {ns}")
        try:
            response = dns_resolver.resolve(ns, rdtype=rdatatype.A)
        except DNSTimeoutError:
            logger.warning(f"DNS Timeout {ns} A")
            continue
        except DNSException as ex:
            logger.warning(ex, exc_info=True)
            continue
        except ConnectionResetError:
            logger.warning(f"Connection reset by peer {ns} A")
            continue
        except ConnectionError:
            logger.warning(f"Name or service not known {ns} A")
            continue
        nameservers += [i.to_text() for i in response.rrset]
    for ns in [i.to_text() for i in response.rrset]:
        logger.info(f"Checking AAAA for {ns}")
        try:
            response = dns_resolver.resolve(ns, rdtype=rdatatype.AAAA)
        except DNSTimeoutError:
            logger.warning(f"DNS Timeout {ns} AAAA")
            continue
        except DNSException as ex:
            logger.warning(ex, exc_info=True)
            continue
        except ConnectionResetError:
            logger.warning(f"Connection reset by peer {ns} AAAA")
            continue
        except ConnectionError:
            logger.warning(f"Name or service not known {ns} AAAA")
            continue
        nameservers += [i.to_text() for i in response.rrset]
    if not nameservers:
        logger.warning("No nameservers found")
        return None
    for ns in nameservers:
        logger.info(f"Trying to resolve DNSKEY using NS {ns}")
        try:
            request = message.make_query(
                domain_name, rdatatype.DNSKEY, want_dnssec=True
            )
            response = query.udp(request, ns, timeout=2)
        except DNSTimeoutError:
            logger.warning("DNSKEY DNS Timeout")
            continue
        except DNSException as ex:
            logger.warning(ex, exc_info=True)
            continue
        except ConnectionResetError:
            logger.warning("DNSKEY Connection reset by peer")
            continue
        except ConnectionError:
            logger.warning("DNSKEY Name or service not known")
            continue
        if response.rcode() != 0:
            logger.warning("No DNSKEY record")
            continue

        logger.info(f"{ns} answered {response.answer}")
        if len(response.answer) == 2:
            return response.answer
        answers += response.answer
        if len(answers) == 2:
            return answers

    return (
        get_dnssec_answer(tldext.registered_domain)
        if tldext.registered_domain != domain_name
        else None
    )


def dnssec_valid(domain_name) -> bool:
    answer = get_dnssec_answer(domain_name)
    if answer is None:
        return False
    if len(answer) != 2:
        logger.warning(f"DNSKEY answer too many values {len(answer)}")
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


def get_caa(domain_name: str):
    tldext = TLDExtract(cache_dir="/tmp")(f"http://{domain_name}")
    try_apex = tldext.registered_domain != domain_name
    response = None
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    try:
        response = resolver.resolve(domain_name, rdatatype.CAA)
    except DNSTimeoutError:
        logger.warning("DNS Timeout")
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
    except ConnectionResetError:
        logger.warning("Connection reset by peer")
    except ConnectionError:
        logger.warning("Name or service not known")
    if not response and try_apex:
        logger.info(f"Trying to resolve CAA for {tldext.registered_domain}")
        return get_caa(tldext.registered_domain)
    if not response:
        return None
    return response


def caa_exist(domain_name: str) -> bool:
    logger.info(f"Trying to resolve CAA for {domain_name}")
    response = get_caa(domain_name)
    if response is None:
        logger.info("No CAA records")
        return False
    issuers = set()
    for rdata in response:
        common_name, *rest = rdata.value.decode().split(";")
        issuers.add(common_name.strip())

    return len(issuers) > 0


def caa_valid(domain_name: str, cert: X509, certificate_chain: list[X509]) -> bool:
    extractor = TLDExtract(cache_dir="/tmp")
    response = get_caa(domain_name)
    if response is None:
        return False
    wild_issuers = set()
    issuers = set()
    for rdata in response:
        caa, *_ = rdata.value.decode().split(";")
        if "issuewild" in rdata.to_text():
            wild_issuers.add(caa.strip())
    for rdata in response:
        caa, *_ = rdata.value.decode().split(";")
        # issuewild tags take precedence over issue tags when specified.
        if caa not in wild_issuers:
            issuers.add(caa.strip())

    issuer = issuer_from_chain(cert, certificate_chain)
    if not isinstance(issuer, X509):
        logger.warning("Issuer certificate not found in chain")
        return False

    common_name = cert.get_subject().CN
    if not common_name:
        return False
    issuer_cn = issuer.get_subject().O
    for caa in wild_issuers:
        issuer_common_names: list[str] = constants.CAA_DOMAINS.get(caa, [])
        if not issuer_common_names:
            issuer_ext = extractor(f"http://{caa}")
            issuer_apex = issuer_ext.registered_domain
            issuer_common_names = constants.CAA_DOMAINS.get(issuer_apex, [])
        if issuer_cn in issuer_common_names:
            return True

    if common_name.startswith("*."):
        return False

    for caa in issuers:
        issuer_common_names: list[str] = constants.CAA_DOMAINS.get(caa, [])
        if not issuer_common_names:
            issuer_ext = extractor(f"http://{caa}")
            issuer_apex = issuer_ext.registered_domain
            issuer_common_names = constants.CAA_DOMAINS.get(issuer_apex, [])
        if issuer_cn in issuer_common_names:
            return True

    return False


@retry(SSL.WantReadError, tries=3, delay=0.5)
def do_handshake(conn):
    try:
        conn.do_handshake()
    except KeyboardInterrupt:
        return
    except SSL.SysCallError:
        pass


def average(values: list):
    return sum(values) / len(values)


def get_certificates(leaf: X509, certificates: list[X509]) -> list[BaseCertificate]:
    roots: list[X509] = []
    ret_certs = [LeafCertificate(leaf)]
    leaf_aki = tlstrust_util.get_key_identifier_hex(
        leaf.to_cryptography(),
        extension=extensions.AuthorityKeyIdentifier,
        key="key_identifier",
    )
    leaf_ski = tlstrust_util.get_key_identifier_hex(
        leaf.to_cryptography(), extension=extensions.SubjectKeyIdentifier, key="digest"
    )
    aki_lookup = {leaf_aki: [leaf]}
    for cert in certificates:
        aki = tlstrust_util.get_key_identifier_hex(
            cert.to_cryptography(),
            extension=extensions.AuthorityKeyIdentifier,
            key="key_identifier",
        )
        if not aki:
            ret_certs.append(RootCertificate(cert))
            continue
        aki_lookup.setdefault(aki, [])
        aki_lookup[aki].append(cert)
        for _, context_type in STORES.items():
            try:
                ret = tlstrust_util.get_certificate_from_store(aki, context_type)
            except FileExistsError:
                continue
            root_ski = tlstrust_util.get_key_identifier_hex(
                ret.to_cryptography(),
                extension=extensions.SubjectKeyIdentifier,
                key="digest",
            )
            if root_ski not in [
                tlstrust_util.get_key_identifier_hex(
                    c.to_cryptography(),
                    extension=extensions.SubjectKeyIdentifier,
                    key="digest",
                )
                for c in roots
            ]:
                roots.append(ret)

    def next_chain(ski: str, lookup: dict, depth: int = 0):
        for next_cert in lookup[ski]:
            next_ski = tlstrust_util.get_key_identifier_hex(
                next_cert.to_cryptography(),
                extension=extensions.SubjectKeyIdentifier,
                key="digest",
            )
            ret_certs.append(
                IntermediateCertificate(next_cert)
                if next_ski != leaf_ski
                else LeafCertificate(next_cert)
            )
            if next_ski in lookup and depth < MAX_DEPTH:
                depth += 1
                next_chain(next_ski, lookup, depth)

    for cert in roots:
        ski = tlstrust_util.get_key_identifier_hex(
            cert.to_cryptography(),
            extension=extensions.SubjectKeyIdentifier,
            key="digest",
        )
        ret_certs.append(RootCertificate(cert))
        if ski in aki_lookup:
            next_chain(ski, aki_lookup)

    return list({v.sha1_fingerprint: v for v in ret_certs}.values())


def html_find_match(content: str, find: str) -> Union[str, None]:
    results = None
    soup = bs(content, "html.parser")
    something = soup.find(find)
    if something and isinstance(something.string, str):
        results = something.string.strip()

    return results


def camel_to_snake(s):
    return "".join(["_" + c.lower() if c.isupper() else c for c in s]).lstrip("_")


def sign_request(
    client_id: str,
    secret_key: str,
    request_url: str,
    request_method: str = "GET",
    raw_body: str = None,
) -> str:
    """Generates and returns the Authorization HTTP header value for Trivial Scanner API
    :param client_id: Registered client name as this machine ID for Trivial Scanner API
    :type client_id: str
    :param secret_key: Registration Token for the provided client
    :type secret_key: str
    :param request_url: The canonical URL of the request being signed
    :type request_url: str
    :param method: HTTP method being used (default GET)
    :type method: str
    :returns: a string representing the header value for Authorization
    :rtype: str
    """
    epochtime = int(datetime.now().timestamp())
    parsed_url = urlparse(request_url)
    port = 443 if parsed_url.port is None else parsed_url.port
    bits = []
    bits.append(request_method.upper())
    bits.append(parsed_url.hostname.lower())
    bits.append(str(port))
    bits.append(parsed_url.path)
    bits.append(str(epochtime))
    if raw_body:
        bits.append(b64encode(raw_body.encode("utf8")).decode("utf8"))
    canonical_string = "\n".join(bits)
    logger.debug(f"canonical_string\n{canonical_string}")
    digest = hmac.new(
        secret_key.encode("utf8"), canonical_string.encode("utf8"), hashlib.sha512
    ).hexdigest()
    return f'HMAC id="{client_id}", mac="{digest}", ts="{epochtime}"'


def clean_nones(value):
    """
    Recursively remove all None values from dictionaries and lists, and returns
    the result as a new dictionary or list.
    """
    if isinstance(value, list):
        return [clean_nones(x) for x in value if x is not None]
    elif isinstance(value, dict):
        return {key: clean_nones(val) for key, val in value.items() if val is not None}
    else:
        return value


def make_data(
    config: dict,
    queries: list[dict],
) -> dict:
    return {
        "generator": "trivialscan",
        "account_name": config.get("account_name"),
        "client_name": config.get("client_name"),
        "project_name": config.get("project_name"),
        "targets": [
            f"{target.get('hostname')}:{target.get('port')}"
            for target in config.get("targets")
        ],
        "date": datetime.utcnow().replace(microsecond=0).isoformat(),
        "queries": queries,
    }


def upload_cloud(
    result: dict,
    dashboard_api_url: str,
    hide_progress_bars: bool = False,
    **kwargs,
) -> dict:
    with Progress(
        "{task.description} [progress.percentage]{task.percentage:>3.0f}%",
        BarColumn(),
        DownloadColumn(),
        "•",
        TimeRemainingColumn(
            compact=True,
            elapsed_when_finished=True,
        ),
        "•",
        TransferSpeedColumn(),
        disable=hide_progress_bars,
    ) as upload_progress:
        upload_tasks: dict[str:int] = {}

        def callback(monitor: MultipartEncoderMonitor):
            task_id: Task = upload_tasks[monitor.encoder.fields[0][1][0]]
            if monitor.encoder.finished:
                upload_progress.update(
                    task_id,
                    completed=monitor.encoder.len,
                )
                return
            upload_progress.update(
                task_id,
                completed=monitor.bytes_read,
            )

        request_url = path.join(dashboard_api_url, "store", result["type"])
        authorization_header = sign_request(
            client_id=kwargs.get("client_name"),
            secret_key=kwargs.get("registration_token"),
            request_url=request_url,
            request_method="POST",
            raw_body=result["value"].read().decode("utf8"),
        )
        logger.debug(f"{request_url}\n{authorization_header}")
        encoder = MultipartEncoder([("files", (result["filename"], result["value"]))])
        upload_task_id = upload_progress.add_task(
            f"Uploading {result['filename']}", total=encoder.len
        )
        upload_tasks[result["filename"]] = upload_task_id
        monitor = MultipartEncoderMonitor(encoder, callback)
        try:
            resp = requests.post(
                request_url,
                data=monitor,
                headers={
                    "Content-Type": monitor.content_type,
                    "Authorization": authorization_header,
                    "X-Trivialscan-Account": kwargs.get("account_name"),
                    "X-Trivialscan-Version": kwargs.get("cli_version"),
                },
                timeout=300,
            )
            if resp.status_code == 403:
                upload_progress.console.print(
                    f"[{constants.CLI_COLOR_FAIL}]Missing or bad client Registration Token provided; Hint: run 'trivial auth'[/{constants.CLI_COLOR_FAIL}]"
                )
                return
            if resp.status_code == 201:
                logger.debug(resp.text)
                try:
                    data = json.loads(resp.text)
                except json.JSONDecodeError:
                    data = resp.text
                if not data:
                    upload_progress.console.print(
                        f"[{constants.CLI_COLOR_FAIL}]Bad response from Trivial Security servers[/{constants.CLI_COLOR_FAIL}]"
                    )
                    return
                return data

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
        ) as err:
            logger.warning(err, exc_info=True)
        upload_progress.console.print(
            f"[{constants.CLI_COLOR_FAIL}]Unable to reach the Trivial Security servers[/{constants.CLI_COLOR_FAIL}]"
        )


def _send_files(queries: list, config: dict, flags: dict, duration: int):
    upload_args = {
        "dashboard_api_url": config["dashboard_api_url"],
        "cli_version": config.get("cli_version"),
        "hide_progress_bars": (
            True
            if flags.get("quiet", False)
            else flags.get("hide_progress_bars", False)
        ),
        "registration_token": config.get("token"),
        "account_name": config.get("account_name"),
        "client_name": config.get("client_name"),
    }
    reports = []
    certificates: dict[str, tuple[models.Certificate, str]] = {}
    for data in queries:
        if not data.get("tls"):
            logger.info(
                f'No response from target: {data["transport"]["hostname"]}:{data["transport"]["port"]}'
            )
            return

        logger.info(
            f'Negotiated {data["tls"]["protocol"]["negotiated"]} {data["transport"]["peer_address"]}'
        )
        certs: dict[str, models.Certificate] = {}
        if "certificates" in data:
            del data["certificates"]
        for cert_data in data["tls"].get("certificates", []):
            cert = models.Certificate(**cert_data)  # type: ignore
            certificates[cert.sha1_fingerprint] = (cert, cert_data["pem"])
            certs[cert.sha1_fingerprint] = cert

        if "targets" in data:
            del data["targets"]
        host_data = deepcopy(data)
        host_data["tls"]["certificates"] = list(certs.keys())
        host = models.Host(**host_data)  # type: ignore
        report = models.ReportSummary(
            generator="trivialscan",
            version=config.get("cli_version"),
            date=datetime.utcnow().replace(microsecond=0).isoformat(),
            execution_duration_seconds=duration,
            account_name=config.get("account_name"),
            targets=[host],
            flags=models.Flags(**flags),
            config=models.Config(**config),
            certificates=list(certs.values()),
            client_name=config.get("client_name"),
            **data,
        )
        ret = upload_cloud(
            result={
                "format": "json",
                "type": models.ReportType.REPORT,
                "filename": "summary.json",
                "value": BytesIO(
                    json.dumps(clean_nones(report.dict()), default=str).encode("utf8")
                ),
            },
            **upload_args,
        )
        if not ret or "results_uri" not in ret:
            logger.warning(
                f"[{constants.CLI_COLOR_FAIL}]Failed to upload report to Trivial Security servers[/{constants.CLI_COLOR_FAIL}]"
            )
            return

        report.results_uri = ret["results_uri"]
        reports.append(path.join(config["dashboard_api_url"], report.results_uri))
        report.report_id = report.results_uri.split("/")[-2]
        groups = {
            (data["compliance"], data["version"])
            for evaluation in data["evaluations"]
            for data in evaluation["compliance"]
            if isinstance(data, dict)
        }
        full_report = models.FullReport(**report.dict())  # type: ignore
        for evaluation in data["evaluations"]:
            if evaluation.get("description"):
                del evaluation["description"]

            compliance_results = []
            for uniq_group in groups:
                name, ver = uniq_group
                group = models.ComplianceGroup(compliance=name, version=ver, items=[])
                for compliance_data in evaluation["compliance"]:
                    if (
                        compliance_data["compliance"] != name
                        or compliance_data["version"] != ver
                    ):
                        continue
                    group.items.append(
                        models.ComplianceItem(
                            requirement=compliance_data.get("requirement"),
                            title=compliance_data.get("title"),
                        )
                    )
                if len(group.items) > 0:
                    compliance_results.append(group)

            evaluation["compliance"] = compliance_results

            threats = []
            for threat in evaluation.get("threats", []) or []:
                if threat.get("description"):
                    del threat["description"]
                if threat.get("technique_description"):
                    del threat["technique_description"]
                if threat.get("sub_technique_description"):
                    del threat["sub_technique_description"]
                threats.append(models.ThreatItem(**threat))
            evaluation["threats"] = threats
            references = evaluation.get("references", []) or []
            del evaluation["references"]
            item = models.EvaluationItem(
                generator=full_report.generator,
                version=full_report.version,
                account_name=config.get("account_name"),  # type: ignore
                client_name=full_report.client_name,
                report_id=report.report_id,
                observed_at=full_report.date,
                transport=host.transport,
                references=[
                    models.ReferenceItem(name=ref["name"], url=ref["url"])
                    for ref in references
                ],
                **evaluation,
            )
            if item.group == "certificate" and item.metadata.get("sha1_fingerprint"):
                item.certificate = certs[item.metadata.get("sha1_fingerprint")]
            full_report.evaluations.append(item)

        upload_cloud(
            result={
                "format": "json",
                "type": models.ReportType.EVALUATIONS,
                "filename": "evaluations.json",
                "value": BytesIO(
                    json.dumps(clean_nones(full_report.dict()), default=str).encode(
                        "utf8"
                    )
                ),
            },
            **upload_args,
        )

    for sha1_fingerprint, cert_data in certificates.items():
        cert, pem = cert_data
        upload_cloud(
            result={
                "format": "pem",
                "type": models.ReportType.CERTIFICATE,
                "filename": f"{sha1_fingerprint}.pem",
                "value": BytesIO(pem.encode("utf8")),
            },
            **upload_args,
        )
    return reports


def update_cloud(
    queries: list, config: dict, flags: dict, duration: int
) -> Union[str, None]:
    try:
        conf = deepcopy(config)
        for item in [
            "evaluations",
            "PCI DSS 4.0",
            "PCI DSS 3.2.1",
            "MITRE ATT&CK 11.2",
        ]:
            if item in conf:
                del conf[item]

        return _send_files(queries, conf, flags, duration)

    except KeyboardInterrupt:
        pass


def get_cname(domain_name: str):
    try:
        answers = resolver.query(domain_name, "CNAME")
        return answers[0].target
    except (
        resolver.NoAnswer,
        resolver.NXDOMAIN,
        DNSTimeoutError,
        DNSException,
        ConnectionResetError,
        ConnectionError,
    ) as ex:
        logger.warning(ex, exc_info=True)
    return None
