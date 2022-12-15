from typing import Union

from ...transport import TLSTransport
from ...certificate import IntermediateCertificate, RootCertificate
from .. import BaseEvaluationTask
from ...util import get_basic_constraints


class EvaluationTask(BaseEvaluationTask):
    def __init__(  # pylint: disable=useless-super-delegation
        self, transport: TLSTransport, metadata: dict, config: dict
    ) -> None:
        super().__init__(transport, metadata, config)
        self._constraints = {}

    def evaluate(self) -> Union[bool, None]:
        self._build_constraints()
        keep_checking = True
        while keep_checking:
            keep_checking = self._check_constraints()
        # now check lengths
        for ski, constraint in self._constraints.items():
            if constraint["path_length"] < len(constraint["intermediates"]):
                self.substitution_metadata["invalid_ski"] = ski
                return False
        return True

    def _build_constraints(self) -> bool:
        new = False
        for cert in self.transport.store.tls_state.certificates:
            if not isinstance(cert, (RootCertificate, IntermediateCertificate)):
                continue
            _, path_length = get_basic_constraints(cert.x509.to_cryptography())
            if isinstance(path_length, int):
                self._constraints[cert.subject_key_identifier] = {
                    "path_length": path_length,
                    "intermediates": set(),
                }
                new = True

        return new

    def _check_constraints(self) -> bool:
        new = False
        for prev_ski, _ in self._constraints.items():
            for cert in self.transport.store.tls_state.certificates:
                if not isinstance(cert, IntermediateCertificate):
                    continue
                if cert.authority_key_identifier == prev_ski:
                    self._constraints[prev_ski]["intermediates"].add(
                        cert.subject_key_identifier
                    )
                if cert.subject_key_identifier in self._constraints:
                    continue
                _, path_length = get_basic_constraints(cert.x509.to_cryptography())
                if (
                    isinstance(path_length, int)
                    and cert.subject_key_identifier not in self._constraints
                ):
                    self._constraints[cert.subject_key_identifier] = {
                        "path_length": path_length,
                        "intermediates": set(),
                    }
                    new = True

        return new
