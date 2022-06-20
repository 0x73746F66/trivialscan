import hashlib
import logging
from datetime import datetime
from ssl import PEM_cert_to_DER_cert
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import extensions, PolicyInformation
from OpenSSL.crypto import (
    X509,
    dump_certificate,
    FILETYPE_PEM,
    TYPE_RSA,
    TYPE_DSA,
    TYPE_DH,
    TYPE_EC,
)
from dns.resolver import Answer
from . import util, constants

__module__ = "trivialscan.certificate"

logger = logging.getLogger(__name__)


class BaseCertificate:
    x509: X509

    def __init__(self, x509: X509) -> None:
        self.x509 = x509

    @property
    def der(self) -> bytes:
        return PEM_cert_to_DER_cert(self.pem)

    @property
    def pem(self) -> str:
        return util.force_str(dump_certificate(FILETYPE_PEM, self.x509))

    @property
    def version(self) -> int:
        return self.x509.get_version()

    @property
    def public_key_exponent(self) -> int | None:
        if self.x509.get_pubkey().type() in [TYPE_RSA, TYPE_DSA]:
            return self.x509.to_cryptography().public_key().public_numbers().e

        return None

    @property
    def public_key_modulus(self) -> int | None:
        if self.x509.get_pubkey().type() in [TYPE_RSA, TYPE_DSA]:
            return self.x509.to_cryptography().public_key().public_numbers().n

        return None

    @property
    def public_key_curve(self) -> str | None:
        if self.x509.get_pubkey().type() in [TYPE_DH, TYPE_EC]:
            return self.x509.to_cryptography().public_key().curve.name

        return None

    @property
    def public_key_size(self) -> int | None:
        return self.x509.get_pubkey().bits()

    @property
    def public_key_type(self) -> str | None:
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
    def serial_number(self) -> str | None:
        return util.convert_decimal_to_serial_bytes(self.x509.get_serial_number())

    @property
    def serial_number_decimal(self) -> int | None:
        return self.x509.get_serial_number()

    @property
    def serial_number_hex(self) -> str | None:
        return "{0:#0{1}x}".format(
            self.x509.get_serial_number(), 4
        )  # pylint: disable=consider-using-f-string

    @property
    def extensions(self) -> list[dict]:
        return util.get_certificate_extensions(self.x509.to_cryptography())

    @property
    def subject(self) -> str:
        return " ".join(
            f"{name.decode():s}={value.decode():s}"
            for name, value in self.x509.get_subject().get_components()
        )

    @property
    def subject_rfc4514(self) -> str:
        return self.x509.to_cryptography().subject.rfc4514_string()

    @property
    def signature_algorithm(self) -> str | None:
        return self.x509.get_signature_algorithm().decode("ascii")

    @property
    def sha256_fingerprint(self) -> str | None:
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
    def subject_key_identifier(self) -> str | None:
        for ext in self.extensions:
            if ext["name"] == "subjectKeyIdentifier":
                return ext[ext["name"]]
        return None

    @property
    def authority_key_identifier(self) -> str | None:
        for ext in self.extensions:
            if ext["name"] == "authorityKeyIdentifier":
                return ext[ext["name"]]
        return None

    @property
    def is_self_signed(self) -> bool:
        return util.is_self_signed(self.x509.to_cryptography())

    @property
    def validation_oid(self) -> str | None:
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
    def revocation_ocsp_stapling(self) -> bool:
        pass

    @property
    def revocation_ocsp_url(self) -> str | None:
        for ext in self.extensions:
            if ext.get("authorityInfoAccess"):
                for info in ext["authorityInfoAccess"]:
                    if info["access_method"] == "OCSP":
                        return info["access_location"]
        return None

    @property
    def revocation_ocsp_must_staple(self) -> bool:
        pass

    @property
    def revocation_ocsp_status(self) -> str:
        pass

    @property
    def revocation_ocsp_response(self) -> str:
        pass

    @property
    def revocation_ocsp_reason(self) -> str:
        pass

    @property
    def revocation_ocsp_time(self) -> str:
        pass

    @property
    def transparency(self) -> bool:
        pass

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


class RootCertificate(BaseCertificate):
    def __init__(self, x509: X509) -> None:  # pylint: disable=useless-super-delegation
        super().__init__(x509)

    @property
    def trust_stores(self) -> list[dict]:
        return []

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
    _hostname: str
    _certification_authority_authorization: bool
    _dnssec: bool
    _dnssec_answer: Answer
    _dnssec_valid: bool
    _dnssec_algorithm: str

    def __init__(self, x509: X509, hostname: str) -> None:
        super().__init__(x509)
        self._hostname = hostname
        self._certification_authority_authorization = None
        self._dnssec = None
        self._dnssec_answer = None
        self._dnssec_valid = None
        self._dnssec_algorithm = None

    @property
    def certification_authority_authorization(self) -> bool:
        if not isinstance(self._certification_authority_authorization, bool):
            self._certification_authority_authorization = util.caa_exist(self._hostname)
        return self._certification_authority_authorization

    @property
    def dnssec(self) -> bool:
        if not isinstance(self._dnssec_answer, Answer):
            self._dnssec_answer = util.get_dnssec_answer(self._hostname)
        if not isinstance(self._dnssec, bool):
            self._dnssec = isinstance(self._dnssec_answer, Answer)
        return self._dnssec

    @property
    def dnssec_valid(self) -> bool:
        if not isinstance(self._dnssec_valid, bool):
            self._dnssec_valid = util.dnssec_valid(self._hostname)
        return self._dnssec_valid

    @property
    def dnssec_algorithm(self) -> str | None:
        if isinstance(self._dnssec_algorithm, str):
            return self._dnssec_algorithm
        if not isinstance(self._dnssec_answer, Answer):
            self._dnssec_answer = util.get_dnssec_answer(self._hostname)
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
        tlsa_dns = util.get_tlsa_answer(self._hostname)
        return isinstance(tlsa_ext, extensions.Extension) or tlsa_dns is not None

    def to_dict(self) -> dict:
        ret = super().to_dict()
        ret["type"] = "leaf"
        return ret
