from ...transport import TLSTransport
from .. import constants, BaseEvaluationTask, EvaluationResult

__version__ = "NIST SP800-131A (strict mode)"


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
                    "strict mode" != compliance["version"]
                    or "NIST SP800-131A" != compliance["compliance"]
                ):
                    continue
                violations.add(evaluation_result.name)

        if self.transport.store.tls_state.negotiated_protocol not in [
            "TLSv1.2 (0x303)",
            "TLSv1.3 (0x304)",
        ]:
            violations.add("Deprecated TLS protocol negotiated")

        non_compliant_ciphers = set()
        for offered_cipher in self.transport.store.tls_state.offered_ciphers:
            for (
                openssl_cipher,
                rfc_cipher,
            ) in constants.NIST_SP800_131A_ALLOWED_RFC_CIPHERS.items():
                if offered_cipher == openssl_cipher:
                    non_compliant_ciphers.add(rfc_cipher)
        if len(non_compliant_ciphers) > 0:
            violations.add("non-compliant cipher offered")
            self.substitution_metadata[f"{__version__} non-compliant ciphers"] = sorted(
                list(non_compliant_ciphers)
            )

        enforce_secp256r1 = "AES128" in self.transport.store.tls_state.negotiated_cipher
        enforce_secp384r1 = "AES256" in self.transport.store.tls_state.negotiated_cipher
        for cert in self.transport.store.tls_state.certificates:
            if cert.public_key_size < constants.NIST_SP800_131A_KEY_SIZES.get(
                cert.public_key_type, 0
            ):
                violations.add("Known Weak key usage")
            if enforce_secp256r1 and cert.public_key_curve != "secp256r1":
                violations.add("curve secp256r1 MUST be used for AES128 ciphers")
            if enforce_secp384r1 and cert.public_key_curve != "secp384r1":
                violations.add("curve secp384r1 MUST be used for AES256 ciphers")

        self.substitution_metadata[f"{__version__} violations"] = list(violations)
        return len(violations) == 0
