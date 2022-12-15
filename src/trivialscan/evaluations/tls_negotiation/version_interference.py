from ...transport import TLSTransport
from ... import constants
from .. import BaseEvaluationTask


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        self.tls_version_interference_versions = set()
        super().__init__(transport, metadata, config)

    def evaluate(self):
        """
        A rejected connection (typically the oldest or latest version, currently 1.3)
        when no mutual accepted TLS version can be negotiates is known as tls interference
        """
        for check_interference in [
            constants.TLS1_3_LABEL,
            constants.TLS1_2_LABEL,
            constants.TLS1_1_LABEL,
            constants.TLS1_0_LABEL,
            constants.SSL3_LABEL,
            constants.SSL2_LABEL,
        ]:
            if (
                check_interference
                not in self.transport.store.tls_state.offered_tls_versions
            ):
                self.tls_version_interference_versions.add(check_interference)

        self.substitution_metadata["tls_version_interference_versions"] = list(
            self.tls_version_interference_versions
        )
        return len(self.tls_version_interference_versions) > 0
