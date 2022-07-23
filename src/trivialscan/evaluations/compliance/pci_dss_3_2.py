from ...transport import TLSTransport
from ... import constants
from .. import BaseEvaluationTask, EvaluationResult

__version__ = "3.2.1"

WEAK_KEY_SIZE = {
    "RSA": 2048,
    "DSA": 2048,
    "EC": 256,
    "DH": 256,
}
WEAK_CIPHER_BITS = 128
PCIDSS_NON_COMPLIANCE_WEAK_KEY_RSA = f'PCI DSS version {__version__} compliance requires RSA public key bits to greater than {WEAK_KEY_SIZE["RSA"]}'
PCIDSS_NON_COMPLIANCE_WEAK_KEY_DSA = f'PCI DSS version {__version__} compliance requires DSA public key bits to greater than {WEAK_KEY_SIZE["DSA"]}'
PCIDSS_NON_COMPLIANCE_WEAK_KEY_EC = f'PCI DSS version {__version__} compliance requires Elliptic curve public key bits to greater than {WEAK_KEY_SIZE["EC"]}'
PCIDSS_NON_COMPLIANCE_WEAK_KEY_DH = f'PCI DSS version {__version__} compliance requires Diffie-Hellman exchange public key bits to greater than {WEAK_KEY_SIZE["DH"]}'
PCIDSS_NON_COMPLIANCE_WEAK_PROTOCOL = f"PCI DSS version {__version__} compliance requires deprecated and known weak TLS protocols are not supported"
PCIDSS_NON_COMPLIANCE_CIPHER = f"PCI DSS version {__version__} compliance requires cipher bits to greater than {WEAK_CIPHER_BITS}, not be of Anonymous key exchange suites, Exchange ciphers, or other known weak ciphers as thy are discovered"
PCIDSS_NON_COMPLIANCE_KNOWN_VULNERABILITIES = f"PCI DSS version {__version__} compliance requires that no known vulnerabilities are present"
PCIDSS_NON_COMPLIANCE_CA_TRUST = f"PCI DSS version {__version__} compliance requires a complete Certificate chain with verified trust anchor"
PCIDSS_NON_COMPLIANCE_WEAK_ALGORITHMS = f"PCI DSS version {__version__} compliance requires deprecated and known weak algorithms are not supported"


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
                    __version__ != compliance["version"]
                    or "PCI DSS" != compliance["compliance"]
                ):
                    continue
                violations.add(compliance["requirement"])

        self.substitution_metadata[f"PCI DSS {__version__} violations"] = list(
            violations
        )
        return len(violations) == 0
