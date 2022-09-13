from ...transport import TLSTransport
from .. import constants, BaseEvaluationTask, EvaluationResult

__version__ = "FIPS 140-2 (NIST SP800-131A transition mode)"


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)

    def evaluate(self):
        violations = set()
        for evaluation_result in self.transport.store.evaluations:
            evaluation_result: EvaluationResult
            if evaluation_result.result_level != constants.RESULT_LEVEL_FAIL:
                continue
            for compliance in evaluation_result.compliance:
                if (
                    "transition mode" != compliance["version"]
                    or "NIST SP800-131A" != compliance["compliance"]
                ):
                    continue
                violations.add(evaluation_result.name)

        non_compliant_strict_ciphers = set()
        for offered_cipher in self.transport.store.tls_state.offered_ciphers:
            rfc_cipher = constants.OPENSSL_MAP_TO_RFC.get(
                offered_cipher, offered_cipher
            )
            if (
                offered_cipher
                not in constants.NIST_SP800_131A_ALLOWED_RFC_CIPHERS.keys()
            ):
                non_compliant_strict_ciphers.add(rfc_cipher)

        non_compliant_ciphers = set()
        for non_compliant_strict_cipher in non_compliant_strict_ciphers:
            if (
                non_compliant_strict_cipher
                not in constants.NIST_SP800_131A_ALLOWED_TRANSITION_CIPHERS.keys()
            ):
                non_compliant_ciphers.add(non_compliant_strict_cipher)

        if len(non_compliant_ciphers) > 0:
            violations.add("non-compliant cipher offered")
            self.substitution_metadata[f"{__version__} non-compliant ciphers"] = sorted(
                list(non_compliant_ciphers)
            )

        for cert in self.transport.store.tls_state.certificates:
            if cert.public_key_size < 80:
                violations.add("Known Weak key usage")

        self.substitution_metadata[f"{__version__} violations"] = list(violations)
        return len(violations) == 0
