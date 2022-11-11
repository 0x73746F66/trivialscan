import hashlib
import logging
from urllib.parse import quote
from typing import cast
from datetime import datetime
from ssl import PEM_cert_to_DER_cert
from typing import Union

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import (
    extensions,
    oid,
    PolicyInformation,
    UnrecognizedExtension,
    ExtensionOID,
    PrecertificateSignedCertificateTimestamps,
)
from cryptography.x509.ocsp import (
    OCSPResponse,
    load_der_ocsp_response,
    OCSPResponseStatus,
    OCSPCertStatus,
)
from OpenSSL.crypto import (
    X509,
    dump_certificate,
    load_certificate,
    FILETYPE_PEM,
    TYPE_RSA,
    TYPE_DSA,
    TYPE_DH,
    TYPE_EC,
)
from tlstrust import TrustStore
from dns.resolver import Answer

from . import util, constants

__module__ = "trivialscan.certificate"

logger = logging.getLogger(__name__)


class BaseCertificate:
    pem: str

    def __init__(self, x509: X509) -> None:
        self.pem = util.force_str(dump_certificate(FILETYPE_PEM, x509))

    @property
    def der(self) -> bytes:
        return PEM_cert_to_DER_cert(self.pem)

    @property
    def x509(self) -> X509:
        return load_certificate(FILETYPE_PEM, self.pem)

    @property
    def version(self) -> int:
        return self.x509.get_version()

    @property
    def public_key_exponent(self) -> Union[int, None]:
        if self.x509.get_pubkey().type() in [TYPE_RSA, TYPE_DSA]:
            return self.x509.to_cryptography().public_key().public_numbers().e

        return None

    @property
    def public_key_modulus(self) -> Union[int, None]:
        if self.x509.get_pubkey().type() in [TYPE_RSA, TYPE_DSA]:
            return self.x509.to_cryptography().public_key().public_numbers().n

        return None

    @property
    def public_key_curve(self) -> Union[str, None]:
        if self.x509.get_pubkey().type() in [TYPE_DH, TYPE_EC]:
            return self.x509.to_cryptography().public_key().curve.name

        return None

    @property
    def public_key_size(self) -> Union[int, None]:
        return self.x509.get_pubkey().bits()

    @property
    def public_key_type(self) -> Union[str, None]:
        key_type = self.x509.get_pubkey().type()
        if key_type == TYPE_RSA:
            return "RSA"
        if key_type == TYPE_DSA:
            return "DSA"
        if key_type == TYPE_DH:
            return "DH"
        if key_type == TYPE_EC:
            return "EC"
        return None

    @property
    def serial_number(self) -> Union[str, None]:
        return util.convert_decimal_to_serial_bytes(self.x509.get_serial_number())

    @property
    def serial_number_decimal(self) -> Union[int, None]:
        return self.x509.get_serial_number()

    @property
    def serial_number_hex(self) -> Union[str, None]:
        return "{0:#0{1}x}".format(
            self.x509.get_serial_number(), 4
        )  # pylint: disable=consider-using-f-string

    @property
    def extensions(self) -> list[dict]:
        return util.get_certificate_extensions(self.x509.to_cryptography())

    @property
    def subject(self) -> str:
        return self.x509.to_cryptography().subject.rfc4514_string()

    @property
    def subject_common_name(self) -> str:
        for fields in self.x509.to_cryptography().subject:
            current = str(fields.oid)
            if "commonName" in current:
                return fields.value
        return None

    @property
    def issuer(self) -> str:
        return self.x509.to_cryptography().issuer.rfc4514_string()

    @property
    def issuer_common_name(self) -> str:
        for fields in self.x509.to_cryptography().issuer:
            current = str(fields.oid)
            if "commonName" in current:
                return fields.value
        return None

    @property
    def signature_algorithm(self) -> Union[str, None]:
        return self.x509.get_signature_algorithm().decode("ascii")

    @property
    def sha256_fingerprint(self) -> Union[str, None]:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def sha1_fingerprint(self) -> str:
        return hashlib.sha1(self.der).hexdigest()

    @property
    def md5_fingerprint(self) -> str:
        return hashlib.md5(self.der).hexdigest()

    @property
    def spki_fingerprint(self) -> str:
        return hashlib.sha256(
            self.x509.to_cryptography()
            .public_key()
            .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        ).hexdigest()

    @property
    def san(self) -> list[str]:
        return util.get_san(self.x509.to_cryptography())

    @property
    def not_before(self) -> str:
        return datetime.strptime(
            self.x509.get_notBefore().decode("ascii"), constants.X509_DATE_FMT
        ).isoformat()

    @property
    def not_after(self) -> str:
        return datetime.strptime(
            self.x509.get_notAfter().decode("ascii"), constants.X509_DATE_FMT
        ).isoformat()

    @property
    def expired(self) -> bool:
        return self.x509.has_expired()

    @property
    def expiry_status(self) -> str:
        return util.date_diff(self.x509.to_cryptography().not_valid_after)

    @property
    def subject_key_identifier(self) -> Union[str, None]:
        for ext in self.extensions:
            if ext["name"] == "subjectKeyIdentifier":
                return ext[ext["name"]]
        return None

    @property
    def authority_key_identifier(self) -> Union[str, None]:
        for ext in self.extensions:
            if ext["name"] == "authorityKeyIdentifier":
                return ext[ext["name"]]
        return None

    @property
    def is_self_signed(self) -> bool:
        return util.is_self_signed(self.x509.to_cryptography())

    @property
    def validation_oid(self) -> Union[str, None]:
        policies = []
        try:
            policies = (
                self.x509.to_cryptography()  # pylint: disable=protected-access
                .extensions.get_extension_for_class(extensions.CertificatePolicies)
                .value._policies
            )
        except extensions.ExtensionNotFound:
            pass
        for policy in policies:
            if not isinstance(policy, PolicyInformation):
                continue
            if (
                policy.policy_identifier._dotted_string  # pylint: disable=protected-access
                in constants.VALIDATION_OID.keys()  # pylint: disable=consider-iterating-dictionary
            ):
                return (
                    policy.policy_identifier._dotted_string  # pylint: disable=protected-access
                )
        return None

    @property
    def validation_level(self) -> str:
        return constants.VALIDATION_TYPES.get(
            constants.VALIDATION_OID.get(self.validation_oid)
        )

    @property
    def known_compromised(self) -> bool:
        return (
            True
            if self.sha1_fingerprint.upper() in constants.COMPROMISED_SHA1.keys()
            else False
        )  # pylint: disable=consider-iterating-dictionary

    @property
    def revocation_crl_urls(self) -> list[str]:
        urls = set()
        for ext in self.extensions:
            if ext.get("cRLDistributionPoints"):
                for info in ext["cRLDistributionPoints"]:
                    urls.add(info["full_name"])
        return list(urls)

    @property
    def external_refs(self) -> str:
        issuer_cn = util.from_subject(self.x509.to_cryptography().issuer)
        return {
            "crt.sh": f"https://crt.sh/?sha1={self.sha1_fingerprint}",
            "censys.io": f"https://search.censys.io/certificates?q=parsed.fingerprint_sha1%3A{self.sha1_fingerprint}",
            "urlscan.io": f"https://urlscan.io/search/#page.tlsIssuer%3A%22{quote(issuer_cn)}%22"
            if issuer_cn
            else None,
        }

    def to_dict(self) -> dict:
        keys = [
            a
            for a in dir(self)
            if not a.startswith("_")
            and a not in ["der", "x509"]
            and not callable(getattr(self, a))
        ]
        values = [
            getattr(self, a)
            for a in dir(self)
            if not a.startswith("_")
            and a not in ["der", "x509"]
            and not callable(getattr(self, a))
        ]
        ret = dict(zip(keys, values))
        return ret


class ClientCertificate(BaseCertificate):
    def __init__(self, x509: X509) -> None:  # pylint: disable=useless-super-delegation
        super().__init__(x509)

    @property
    def trust_stores(self) -> list[dict]:
        return (
            []
            if not self.subject_key_identifier
            else TrustStore(self.subject_key_identifier).to_dict().get("trust_stores")
        )

    def to_dict(self) -> dict:
        ret = super().to_dict()
        ret["type"] = "client"
        return ret


class RootCertificate(BaseCertificate):
    def __init__(self, x509: X509) -> None:  # pylint: disable=useless-super-delegation
        super().__init__(x509)

    @property
    def trust_stores(self) -> list[dict]:
        return (
            []
            if not self.subject_key_identifier
            else TrustStore(self.subject_key_identifier).to_dict().get("trust_stores")
        )

    def to_dict(self) -> dict:
        ret = super().to_dict()
        ret["type"] = "root"
        return ret


class IntermediateCertificate(BaseCertificate):
    def __init__(self, x509: X509) -> None:  # pylint: disable=useless-super-delegation
        super().__init__(x509)

    def to_dict(self) -> dict:
        ret = super().to_dict()
        ret["type"] = "intermediate"
        return ret


class LeafCertificate(BaseCertificate):
    _certification_authority_authorization: bool
    _dnssec: bool
    _dnssec_answer: Answer
    _dnssec_valid: bool
    _dnssec_algorithm: str
    _ocsp_response: OCSPResponse
    _revocation_ocsp_hash_algorithm: str
    _revocation_ocsp_signature_hash_algorithm: str

    def __init__(self, x509: X509, transport=None) -> None:
        super().__init__(x509)
        self._transport = transport
        self._certification_authority_authorization = None
        self._dnssec = None
        self._dnssec_answer = None
        self._dnssec_valid = None
        self._dnssec_algorithm = None
        self._ocsp_response = None
        self._revocation_ocsp_hash_algorithm = None
        self._revocation_ocsp_signature_hash_algorithm = None

    def set_transport(self, transport):
        self._transport = transport

    @property
    def transparency(self) -> str:
        try:
            sct_ext = self.x509.to_cryptography().extensions.get_extension_for_oid(
                ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
            )
            if isinstance(sct_ext.value, UnrecognizedExtension):
                logger.warning("OpenSSL can't parse the SCT extension")
                return constants.SCT_PRESENT
            sct_ext_value = cast(
                PrecertificateSignedCertificateTimestamps, sct_ext.value
            )
            return (
                constants.SCT_INSUFFICIENT
                if len(sct_ext_value) < 3
                else constants.SCT_GOOD
            )
        except extensions.ExtensionNotFound:
            pass
        return constants.SCT_MISSING

    @property
    def certification_authority_authorization(self) -> bool:
        if not isinstance(self._certification_authority_authorization, bool):
            self._certification_authority_authorization = util.caa_exist(
                self._transport.store.tls_state.hostname
            )
        return self._certification_authority_authorization

    @property
    def dnssec(self) -> bool:
        if not isinstance(self._dnssec_answer, Answer):
            self._dnssec_answer = util.get_dnssec_answer(
                self._transport.store.tls_state.hostname
            )
        if not isinstance(self._dnssec, bool):
            self._dnssec = isinstance(self._dnssec_answer, Answer)
        return self._dnssec

    @property
    def dnssec_algorithm(self) -> Union[str, None]:
        if isinstance(self._dnssec_algorithm, str):
            return self._dnssec_algorithm
        if not isinstance(self._dnssec_answer, Answer):
            self._dnssec_answer = util.get_dnssec_answer(
                self._transport.store.tls_state.hostname
            )
        if isinstance(self._dnssec_answer, Answer):
            algorithm = int(self._dnssec_answer[0].to_text().split()[6])
            self._dnssec_algorithm = (
                algorithm
                if algorithm not in constants.DNSSEC_ALGORITHMS
                else constants.DNSSEC_ALGORITHMS[algorithm]
            )
        return self._dnssec_algorithm

    @property
    def tlsa(self) -> bool:
        tlsa_ext = util.get_extensions_by_oid(
            self.x509.to_cryptography(), constants.TLSA_EXTENSION_OID
        )
        tlsa_dns = util.get_tlsa_answer(self._transport.store.tls_state.hostname)
        return isinstance(tlsa_ext, extensions.Extension) or tlsa_dns is not None

    @property
    def revocation_ocsp_urls(self) -> list:
        return list(
            set(
                info["access_location"]
                for ext in self.extensions
                if ext.get("authorityInfoAccess")
                for info in ext["authorityInfoAccess"]
                if info["access_method"] == "OCSP"
            )
        )

    @property
    def revocation_ocsp_stapling(self) -> Union[bool, None]:
        assertion = self._transport._revocation_ocsp_assertion or b""
        response = None
        if assertion == b"":
            try:
                ext = self.x509.to_cryptography().extensions.get_extension_for_class(
                    extensions.AuthorityInformationAccess
                )
                if ext:
                    uris = [
                        desc.access_location.value
                        for desc in ext.value
                        if desc.access_method == oid.AuthorityInformationAccessOID.OCSP
                    ]
                    for uri in uris:
                        logger.debug(
                            f"{self._transport.store.tls_state.hostname}:{self._transport.store.tls_state.port} Requesting OCSP from responder {uri}"
                        )
                        response = self._transport.get_ocsp_response(uri)
                        if response is None:
                            continue
            except extensions.ExtensionNotFound:
                pass  # no responders
        if response is None and assertion != b"":
            return True

        return False

    @property
    def revocation_ocsp_must_staple(self) -> bool:
        ext = None
        try:
            ext = self.x509.to_cryptography().extensions.get_extension_for_class(
                extensions.TLSFeature
            )
        except extensions.ExtensionNotFound:
            pass
        if ext:
            for feature in ext.value:
                if feature in [
                    extensions.TLSFeatureType.status_request,
                    extensions.TLSFeatureType.status_request_v2,
                ]:
                    return True
        return False

    @property
    def revocation_ocsp_status(self) -> str:
        if self._ocsp_response:
            status = self._ocsp_response.certificate_status
            return constants.OCSP_CERT_STATUS.get(
                status, constants.OCSP_CERT_STATUS[OCSPCertStatus.UNKNOWN]
            )

        assertion = self._transport._revocation_ocsp_assertion or b""
        if assertion == b"" and self.revocation_ocsp_must_staple:
            return constants.OCSP_MUST_STAPLE_NOT_STAPLED
        try:
            ext = self.x509.to_cryptography().extensions.get_extension_for_class(
                extensions.AuthorityInformationAccess
            )
            if ext is None:
                return (
                    constants.OCSP_STAPLED_BUT_NOT_REQUIRED
                    if assertion != b""
                    else constants.OCSP_NO_RESPONDER_URL
                )
        except extensions.ExtensionNotFound:
            return (
                constants.OCSP_STAPLED_BUT_NOT_REQUIRED
                if assertion != b""
                else constants.OCSP_NO_RESPONDER_URL
            )

        responders = [
            desc.access_location.value
            for desc in ext.value
            if desc.access_method == oid.AuthorityInformationAccessOID.OCSP
        ]
        if not responders:
            return (
                constants.OCSP_STAPLED_NO_RESPONDER_URL
                if assertion != b""
                else constants.OCSP_NO_RESPONDER_URL
            )

        self._ocsp_response = (
            load_der_ocsp_response(assertion) if assertion != b"" else None
        )
        if not self._ocsp_response:
            for uri in responders:
                logger.info(
                    f"SHA1:{self.sha1_fingerprint} Requesting OCSP from responder {uri}"
                )
                self._ocsp_response = self._transport.get_ocsp_response(uri)
                if self._ocsp_response:
                    break
        if not self._ocsp_response:
            logger.warning(
                f"SHA1:{self.sha1_fingerprint} OCSP response is not available"
            )
            return constants.OCSP_NO_ASSERTION
        logger.info(f"SHA1:{self.sha1_fingerprint} OCSP response received")
        self._revocation_ocsp_hash_algorithm = self._ocsp_response.hash_algorithm.name
        self._revocation_ocsp_signature_hash_algorithm = (
            self._ocsp_response.signature_hash_algorithm.name
        )
        if self._ocsp_response.this_update > datetime.utcnow():
            logger.error(
                f"SHA1:{self.sha1_fingerprint} OCSP thisUpdate is future dated"
            )
            return constants.OCSP_INVALID_ASSERTION_DATE
        status = self._ocsp_response.certificate_status
        return constants.OCSP_CERT_STATUS.get(
            status, constants.OCSP_CERT_STATUS[OCSPCertStatus.UNKNOWN]
        )

    @property
    def revocation_ocsp_hash_algorithm(self) -> str:
        logger.debug(self.revocation_ocsp_status)
        return self._revocation_ocsp_hash_algorithm

    @property
    def revocation_ocsp_signature_hash_algorithm(self) -> str:
        logger.debug(self.revocation_ocsp_status)
        return self._revocation_ocsp_signature_hash_algorithm

    @property
    def revocation_ocsp_response(self) -> str:
        logger.debug(self.revocation_ocsp_status)
        if not self._ocsp_response:
            return constants.OCSP_RESP_STATUS[OCSPResponseStatus.TRY_LATER]
        status = self._ocsp_response.response_status
        return constants.OCSP_RESP_STATUS.get(
            status, constants.OCSP_RESP_STATUS[OCSPResponseStatus.TRY_LATER]
        )

    @property
    def revocation_ocsp_reason(self) -> str:
        logger.debug(self.revocation_ocsp_status)
        return (
            ""
            if not self._ocsp_response or not self._ocsp_response.revocation_reason
            else self._ocsp_response.revocation_reason.value
        )

    @property
    def revocation_ocsp_time(self) -> str:
        logger.debug(self.revocation_ocsp_status)
        return (
            ""
            if not self._ocsp_response or not self._ocsp_response.revocation_time
            else self._ocsp_response.revocation_time.isoformat()
        )

    @property
    def revocation_ocsp_result(self) -> bool:
        logger.debug(self.revocation_ocsp_status)
        return (
            False
            if not self._ocsp_response
            else (
                self._ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL
                and self._ocsp_response.certificate_status == OCSPCertStatus.GOOD
            )
        )

    def to_dict(self) -> dict:
        ret = super().to_dict()
        ret["type"] = "leaf"
        return ret
