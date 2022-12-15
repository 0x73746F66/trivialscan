import logging
from ...constants import PROTOCOL_VERSION, FAKE_PROTOCOLS
from ...transport import TLSTransport
from .. import BaseEvaluationTask

logger = logging.getLogger(__name__)


class EvaluationTask(BaseEvaluationTask):
    probe_info: str = "Negotiating fake TLS versions"

    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        self.tls_version_intolerance_versions = set()
        super().__init__(transport, metadata, config)

    def evaluate(self):
        """
        Protocol not understood by the server, the server should negotiate the highest protocol it knows
        A rejected connection indicates TLS version intolerance, and is not rfc5246 or rfc8446 compliant
        """
        logger.info("Trying to derive TLS version intolerance")
        for fake_proto in FAKE_PROTOCOLS:
            fake_ver = PROTOCOL_VERSION[fake_proto]
            label = f"{fake_proto} ({hex(fake_ver)})"
            if self.version_intolerance(fake_ver):
                self.tls_version_intolerance_versions.add(label)

        self.substitution_metadata["tls_version_intolerance_versions"] = list(
            self.tls_version_intolerance_versions
        )
        return len(self.tls_version_intolerance_versions) > 0

    def version_intolerance(self, version: int) -> bool:
        tspt = TLSTransport(
            hostname=self.transport.store.tls_state.hostname,
            port=self.transport.store.tls_state.port,
        )
        try:
            if tspt.specify_tls_version(
                min_tls_version=version,
                use_sni=self.transport.store.tls_state.sni_support,
            ):
                return False

        except Exception as ex:
            logger.debug(ex, exc_info=True)
        return True
