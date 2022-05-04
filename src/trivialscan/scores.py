from datetime import datetime
from tlstrust.context import BROWSERS, PLATFORMS
from tlstrust import TrustStore
from .nist import WEAK_CIPHER_BITS
from .metadata import Metadata
from . import (
    constants,
    Validator,
    LeafCertValidator,
    RootCertValidator,
    PeerCertValidator,
)
from .validator import VALIDATION_VALID_CAA, VALIDATION_MESSAGES


BASE_SCORE = 2500
MINOR_MOD = 50
MAJOR_MOD = 100
WEAKNESS_MOD = -75
ISSUE_MOD = -125
MAJOR_LABEL = "Best configuration"
MINOR_LABEL = "Good configuration"
UNSCORED_LABEL = "Unscored configuration"
WEAKNESS_LABEL = "Weak configuration"
ISSUE_LABEL = "Configuration issues"

# No matter the score, if these validations occur they are capped at the specified rating
MAX_SCORING_FLAGS = {
    RootCertValidator: {
        "C": {
            "common_name_defined": False,
        },
        "E": {
            "avoid_known_weak_keys": False,
            "avoid_known_weak_signature_algorithm": False,
            "issued_past_tense": False,
        },
        "F": {
            "not_expired": False,
            "not_revoked": False,
        },
    },
    LeafCertValidator: {
        "B": {
            "ocsp_staple_satisfied": None,
        },
        "C": {
            "common_name_defined": False,
        },
        "D": {
            "ocsp_staple_satisfied": False,
            "avoid_deprecated_dnssec_algorithms": False,
        },
        "E": {
            "certificate_valid_tls_usage": False,
            "valid_caa": False,
            "not_self_signed": False,
            "avoid_known_weak_keys": False,
            "avoid_known_weak_signature_algorithm": False,
            "issued_past_tense": False,
        },
        "F": {
            "ocsp_must_staple_satisfied": False,
            "not_expired": False,
            "not_revoked": False,
            "valid_dnssec": False,
            "basic_constraints_ca": False,
            "avoid_deprecated_protocols": False,
            "match_hostname": False,
            "trusted_ca": False,
            "common_name_valid": False,
        },
    },
    PeerCertValidator: {
        "C": {
            "common_name_defined": False,
        },
        "E": {
            "not_self_signed": False,
            "avoid_known_weak_keys": False,
            "avoid_known_weak_signature_algorithm": False,
            "issued_past_tense": False,
        },
        "F": {
            "not_expired": False,
            "not_revoked": False,
            "basic_constraints_ca": False,
        },
    },
}


class Score:
    _validators: list[Validator]
    scores: dict
    security_score_best: int
    security_score_worst: int
    rating_groups: dict
    rating_cap: str
    rating_cap_reason: list

    def __init__(self, validators: list[Validator]):
        self._validators = validators
        self.rating_cap, self.rating_cap_reason = self._get_max_rating()
        self.scores = {
            "key_size": min(Score.key_size(v.metadata) for v in self._validators),
            "certificate_validation": min(
                Score.certificate_validation(v.metadata)
                for v in self._validators
                if isinstance(v, LeafCertValidator)
            ),
            "caa": min(
                Score.caa(v.metadata)
                for v in self._validators
                if isinstance(v, LeafCertValidator)
            ),
            "dnssec": min(
                Score.dnssec(v.metadata)
                for v in self._validators
                if isinstance(v, LeafCertValidator)
            ),
            "cipher": min(
                Score.cipher(v.metadata)
                for v in self._validators
                if isinstance(v, LeafCertValidator)
            ),
            "transport": min(
                Score.transport(v.metadata)
                for v in self._validators
                if isinstance(v, LeafCertValidator)
            ),
            "risk": min(Score.risk(v.metadata) for v in self._validators),
            "trust": min(Score.trust(v.metadata) for v in self._validators),
            "server_configuration": min(
                Score.server_configuration(v.metadata) for v in self._validators
            ),
            "leaf_validity_period": min(
                Score.leaf_validity_period(v.metadata)
                for v in self._validators
                if isinstance(v, LeafCertValidator)
            ),
            "chain_expiry": min(
                Score.chain_expiry(v.metadata)
                for v in self._validators
                if not isinstance(v, LeafCertValidator)
            ),
        }
        self.security_score_best = BASE_SCORE + (MAJOR_MOD * len(self.scores.keys()))
        self.security_score_worst = BASE_SCORE + (ISSUE_MOD * len(self.scores.keys()))

    @property
    def result(self) -> int:
        results = list(self.scores.values())
        results.append(BASE_SCORE)
        return int(round(sum(results), 0))

    @property
    def rating(self) -> str:
        score_aplus = int(round(self.security_score_best * 0.95, 0))
        score_a = int(round(self.security_score_best * 0.9, 0))
        score_b = int(round(self.security_score_best * 0.85, 0))
        score_c = int(round(self.security_score_best * 0.8, 0))
        score_d = int(round(self.security_score_best * 0.7, 0))
        score_e = int(round(self.security_score_best * 0.5, 0))
        self.rating_groups = {
            "A+": (score_aplus, self.security_score_best),
            "A": (score_a, score_aplus),
            "B": (score_b, score_a),
            "C": (score_c, score_b),
            "D": (score_d, score_c),
            "E": (score_e, score_d),
            "F": (0, score_e),
        }
        ratings = [self.rating_cap]
        for rating, group in self.rating_groups.items():
            low, top = group
            if low <= self.result <= top:
                ratings.append(rating)
                break

        ratings.sort()
        return ratings[-1]

    @property
    def scoring_results(self) -> dict:
        summary = {
            UNSCORED_LABEL: [],
            MAJOR_LABEL: [],
            MINOR_LABEL: [],
            WEAKNESS_LABEL: [],
            ISSUE_LABEL: [],
        }
        for key, result in self.scores.items():
            if result == 0:
                summary[UNSCORED_LABEL].append(key)
            if result == MINOR_MOD:
                summary[MINOR_LABEL].append(f"{key}({self.scores[key]})")
            if result == MAJOR_MOD:
                summary[MAJOR_LABEL].append(f"{key}({self.scores[key]})")
            if result == WEAKNESS_MOD:
                summary[WEAKNESS_LABEL].append(f"{key}({self.scores[key]})")
            if result == ISSUE_MOD:
                summary[ISSUE_LABEL].append(f"{key}({self.scores[key]})")
        return summary

    @property
    def risk_summary(self) -> list[str]:
        mitigations = set()
        issues = set()
        for validator in self._validators:
            if validator.metadata.certificate_known_compromised:
                issues.add(
                    f"Certificate is known to be compromised; {validator.certificate.subject.rfc4514_string()} ({validator.metadata.certificate_sha1_fingerprint})"
                )
            if validator.metadata.possible_phish_or_malicious:
                issues.add(
                    "Connection with server is potentially malicious (e.g. phish)"
                )
            if (
                isinstance(validator, LeafCertValidator)
                and validator.metadata.revocation_ocsp_must_staple
            ):
                mitigations.add(
                    "Certificate uses the OCSP must staple flag which provides a high assurance of revocation controls"
                )
            if (
                isinstance(validator, LeafCertValidator)
                and validator.metadata.revocation_ocsp_stapling
            ):
                mitigations.add(
                    "Certificate uses the OCSP stapling which provides limited revocation controls"
                )
            if (
                isinstance(validator, LeafCertValidator)
                and validator.metadata.http_expect_ct_report_uri
            ):
                mitigations.add(
                    "Connection included Certificate Transparency reporting configuration"
                )
        if not issues:
            issues.add("No critical risks observed")
        if not mitigations:
            mitigations.add("Low maturity of risk mitigations")
        return list(issues) + list(mitigations)

    @property
    def trust_summary(self) -> str:
        # Not Trusted
        for v in self._validators:
            if not isinstance(v, RootCertValidator):
                continue
            any_trust = any(
                [
                    v.metadata.trust_ccadb,
                    v.metadata.trust_android,
                    v.metadata.trust_certifi,
                    v.metadata.trust_java,
                    v.metadata.trust_libcurl,
                    v.metadata.trust_dart,
                    v.metadata.trust_rustls,
                ]
            )
            if not any_trust:
                return constants.NOT_TRUSTED

        for v in self._validators:
            if not isinstance(v, LeafCertValidator):
                continue
            # Questionable Trust branch
            validation_type = constants.VALIDATION_OID[
                v.metadata.certificate_validation_oid
            ]
            if (
                validation_type == "DV"
                and v.metadata.certificate_issuer in constants.QUESTIONABLE_DV_ISSUERS
            ):
                return constants.QUESTIONABLE_TRUST

        # Verified Trust branch
        is_trusted = False
        for v in self._validators:
            if not isinstance(v, RootCertValidator):
                continue
            is_trusted = all(
                [
                    v.metadata.trust_ccadb,
                    v.metadata.trust_android,
                    v.metadata.trust_certifi,
                    v.metadata.trust_java,
                    v.metadata.trust_libcurl,
                    v.metadata.trust_dart,
                    v.metadata.trust_rustls,
                ]
            )
        for v in self._validators:
            if not isinstance(v, LeafCertValidator):
                continue
            if (
                VALIDATION_VALID_CAA in v.validation_checks
                and is_trusted
                and v.validation_checks[VALIDATION_VALID_CAA]
            ):
                return constants.VERIFIED_TRUST
            if is_trusted and (
                VALIDATION_VALID_CAA not in v.validation_checks
                or v.validation_checks[VALIDATION_VALID_CAA] is False
            ):
                return constants.UNVERIFIED_TRUST

        # Specific Trust branch
        for v in self._validators:
            if not isinstance(v, RootCertValidator):
                continue
            trust_store = TrustStore(
                v.metadata.certificate_subject_key_identifier
                if not v.metadata.certificate_authority_key_identifier
                else v.metadata.certificate_authority_key_identifier
            )
            if all(
                [trust_store.check_trust(context) for context in BROWSERS.values()]
            ) and not all(
                [trust_store.check_trust(context) for context in PLATFORMS.values()]
            ):
                return constants.BROWSER_TRUSTED
            if not all(
                trust_store.check_trust(context) for context in BROWSERS.values()
            ) and all(
                trust_store.check_trust(context) for context in PLATFORMS.values()
            ):
                return constants.SERVER_TRUSTED

        return constants.LIMITED_TRUST

    @staticmethod
    def key_size(metadata: Metadata) -> int:
        if metadata.certificate_key_compromised:
            return ISSUE_MOD
        if (
            metadata.certificate_public_key_size
            > constants.WEAK_KEY_SIZE[metadata.certificate_public_key_type] * 3
        ):
            return MAJOR_MOD
        if (
            metadata.certificate_public_key_size
            > constants.WEAK_KEY_SIZE[metadata.certificate_public_key_type] * 2
        ):
            return MINOR_MOD
        return (
            WEAKNESS_MOD
            if metadata.certificate_public_key_size
            == constants.WEAK_KEY_SIZE[metadata.certificate_public_key_type]
            else ISSUE_MOD
        )

    @staticmethod
    def server_configuration(metadata: Metadata) -> int:
        if (
            metadata.tls_version_intolerance
            and constants.TLS1_3_LABEL in metadata.tls_version_intolerance_versions
        ):
            return ISSUE_MOD
        if metadata.tls_long_handshake_intolerance or not metadata.scsv:
            return WEAKNESS_MOD
        if (
            constants.TLS1_3_LABEL in metadata.offered_tls_versions
            and not metadata.tls_version_interference
        ):
            return MAJOR_MOD
        if any(
            [
                constants.TLS1_2_LABEL in metadata.offered_tls_versions,
                constants.TLS1_3_LABEL in metadata.offered_tls_versions,
            ]
        ):
            return MINOR_MOD
        return 0

    @staticmethod
    def trust(metadata: Metadata) -> int:
        if all(
            [
                metadata.trust_ccadb,
                metadata.trust_java,
                metadata.trust_android,
                metadata.trust_certifi,
                metadata.trust_libcurl,
                metadata.trust_dart,
                metadata.trust_rustls,
            ]
        ):
            return MAJOR_MOD
        if metadata.trust_ccadb:
            return MINOR_MOD
        return (
            WEAKNESS_MOD
            if any(
                [
                    metadata.trust_ccadb,
                    metadata.trust_java,
                    metadata.trust_android,
                    metadata.trust_certifi,
                    metadata.trust_libcurl,
                    metadata.trust_dart,
                    metadata.trust_rustls,
                ]
            )
            else ISSUE_MOD
        )

    @staticmethod
    def caa(metadata: Metadata) -> int:
        return (
            MAJOR_MOD
            if metadata.certification_authority_authorization
            else WEAKNESS_MOD
        )

    @staticmethod
    def leaf_validity_period(metadata: Metadata) -> int:
        not_after = datetime.fromisoformat(metadata.certificate_not_after)
        not_before = datetime.fromisoformat(metadata.certificate_not_before)
        now = datetime.utcnow()
        if not_after < now or not_before > now:
            return ISSUE_MOD
        difference = not_after - not_before
        if difference.days <= 365:
            return MAJOR_MOD
        if 366 <= difference.days <= 1825:
            return MINOR_MOD
        return WEAKNESS_MOD

    @staticmethod
    def chain_expiry(metadata: Metadata) -> int:
        not_after = datetime.fromisoformat(metadata.certificate_not_after)
        not_before = datetime.fromisoformat(metadata.certificate_not_before)
        now = datetime.utcnow()
        if not_after < now or not_before > now:
            return ISSUE_MOD
        return 0

    @staticmethod
    def risk(metadata: Metadata) -> int:
        if metadata.certificate_known_compromised:
            return ISSUE_MOD
        if metadata.possible_phish_or_malicious:
            return WEAKNESS_MOD
        return MAJOR_MOD if metadata.revocation_ocsp_must_staple else MINOR_MOD

    @staticmethod
    def transport(metadata: Metadata) -> int:
        major = [
            metadata.http_xss_protection,
            metadata.http_csp,
            metadata.http_hsts,
            metadata.negotiated_protocol not in constants.WEAK_PROTOCOL.keys(),
            not metadata.http2_cleartext_support,
            constants.TLS1_3_LABEL == metadata.preferred_protocol,
        ]
        weak = [
            not metadata.sni_support,
            metadata.compression_support,
            metadata.client_renegotiation,
            metadata.session_resumption_caching,
            metadata.session_resumption_tickets,
            metadata.session_resumption_ticket_hint,
        ]
        if all(major) and not any(weak):
            return MAJOR_MOD
        if any(major) and not all(weak):
            return MINOR_MOD
        if any(weak):
            return WEAKNESS_MOD
        if all(weak):
            return ISSUE_MOD
        return 0

    @staticmethod
    def dnssec(metadata: Metadata) -> int:
        if (
            metadata.dnssec
            and metadata.dnssec_algorithm not in constants.WEAK_DNSSEC_ALGORITHMS.keys()
        ):
            return MAJOR_MOD
        if (
            not metadata.dnssec
            or metadata.dnssec_algorithm in constants.WEAK_DNSSEC_ALGORITHMS.keys()
        ):
            return ISSUE_MOD
        if metadata.tlsa:
            return MINOR_MOD
        return WEAKNESS_MOD

    @staticmethod
    def cipher(metadata: Metadata) -> int:
        if metadata.strong_cipher:
            return MAJOR_MOD
        if metadata.weak_cipher:
            return ISSUE_MOD
        if (
            metadata.forward_anonymity
            or metadata.negotiated_cipher_bits >= WEAK_CIPHER_BITS
        ):
            return MINOR_MOD
        return WEAKNESS_MOD

    @staticmethod
    def certificate_validation(metadata: Metadata) -> int:
        validation_type = constants.VALIDATION_OID[metadata.certificate_validation_oid]
        if validation_type == "OV":
            return MAJOR_MOD
        if validation_type == "EV":
            return MINOR_MOD
        if (
            validation_type == "DV"
            and metadata.certificate_issuer in constants.QUESTIONABLE_DV_ISSUERS
        ):
            return ISSUE_MOD
        if validation_type == "DV":
            return WEAKNESS_MOD
        return 0

    def _get_max_rating(self) -> tuple[str, list[str]]:
        max_rating = "A+"
        matched = []
        violations = {"A+": [], "A": [], "B": [], "C": [], "D": [], "E": [], "F": []}

        def assess(validator: Validator, ratings):
            for check, result in validator.validation_checks.items():
                for rating, flags in ratings.items():
                    if check not in flags.keys():
                        continue
                    if flags[check] is result:
                        matched.append(rating)
                        validation_message = f"{VALIDATION_MESSAGES[check]} {validator.certificate.subject.rfc4514_string()} ({validator.metadata.certificate_sha1_fingerprint})"
                        violations[rating].append(validation_message)

        for validator_type, ratings in MAX_SCORING_FLAGS.items():
            for validator in self._validators:
                if not isinstance(validator, validator_type):
                    continue
                assess(validator, ratings)

        if matched:
            matched.sort()
            max_rating = matched[-1]
        return max_rating, violations[max_rating]
