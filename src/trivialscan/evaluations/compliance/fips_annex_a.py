from ...transport import TLSTransport
from .. import constants, BaseEvaluationTask, EvaluationResult

__version__ = "FIPS 140-2 Annex A"


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
                    "Annex A" != compliance["version"]
                    or "FIPS 140-2" != compliance["compliance"]
                ):
                    continue
                violations.add(evaluation_result.name)

        non_compliant_strict_ciphers = set()
        for offered_cipher in self.transport.store.tls_state.offered_ciphers:
            if offered_cipher not in constants.FIPS_140_2_CIPHERS:
                rfc_cipher = constants.OPENSSL_MAP_TO_RFC.get(
                    offered_cipher, offered_cipher
                )
                non_compliant_strict_ciphers.add(rfc_cipher)

        if len(non_compliant_strict_ciphers) > 0:
            violations.add("Offered non-compliance ciphers")
            self.substitution_metadata[
                f"{__version__} non-compliance ciphers"
            ] = sorted(list(non_compliant_strict_ciphers))

        self.substitution_metadata[f"{__version__} violations"] = list(violations)
        return len(violations) == 0
