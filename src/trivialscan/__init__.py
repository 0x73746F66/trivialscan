import sys
import logging
from importlib import import_module
from copy import deepcopy
from rich.console import Console
from .config import load_config, get_config
from .util import TimeoutError
from .cli import log
from .transport import TLSTransport, HTTPTransport
from .transport.insecure import InsecureTransport
from .certificate import LeafCertificate
from .exceptions import (
    EvaluationNotImplemented,
    EvaluationNotRelevant,
    NoLogEvaluation,
    TransportError,
)
from .evaluations import BaseEvaluationTask
from .outputs import checkpoint

__module__ = "trivialscan"

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
logger = logging.getLogger(__name__)


class Trivialscan:
    _checkpoints: set = set()
    _console: Console = None
    config: dict = get_config(custom_values=load_config())

    def __init__(self, console: Console = None, **kwargs) -> None:
        self.config = kwargs.get("config", self.config)
        self._console = console

    def tls_probe(
        self,
        hostname: str,
        port: int = 443,
        client_certificate: str = None,
    ) -> TLSTransport:
        use_cp = self.config["defaults"].get("checkpoint")
        checkpoint1 = f"resume{hostname}{port}".encode("utf-8")
        try:
            if use_cp and checkpoint.unfinished(checkpoint1):
                transport = checkpoint.resume(checkpoint1)
            else:
                transport = InsecureTransport(hostname, port)
                transport.tmp_path_prefix = self.config["defaults"].get(
                    "tmp_path_prefix", "/tmp"
                )
                if isinstance(client_certificate, str):
                    transport.pre_client_authentication_check(
                        client_pem_path=client_certificate
                    )
                transport.connect_insecure(
                    cafiles=self.config["defaults"].get("cafiles"),
                    use_sni=self.config["defaults"].get("use_sni"),
                )
                if use_cp:
                    checkpoint.set(checkpoint1, transport)
                    self._checkpoints.add(checkpoint1)
        except TransportError as err:
            log(
                f"[light_coral]{type(err).__name__}[/light_coral] {err}",
                hostname=hostname,
                port=port,
                con=self._console,
            )

        return transport

    def http_probe(
        self,
        hostname: str,
        request_path: str,
        port: int = 443,
        client_certificate: str = None,
        tmp_path_prefix: str = config["defaults"].get("tmp_path_prefix", "/tmp"),
    ) -> HTTPTransport:
        transport = HTTPTransport(
            hostname=hostname,
            port=port,
            tmp_path_prefix=tmp_path_prefix,
        )
        transport.do_request(
            http_request_path=request_path,
            cafiles=self.config["defaults"].get("cafiles"),
            client_certificate=client_certificate,
        )

        return transport

    def _shared_config_for_tasks(self) -> dict:
        return {
            "use_sni": self.config["defaults"].get("use_sni"),
            "cafiles": self.config["defaults"].get("cafiles"),
            "tmp_path_prefix": self.config["defaults"].get("tmp_path_prefix"),
        }

    def execute_evaluations(self, transport: TLSTransport):
        if transport.store.tls_state.negotiated_protocol:
            log(
                f"[cyan]INTO![/cyan] Negotiated {transport.store.tls_state.negotiated_protocol} {transport.store.tls_state.peer_address}",
                hostname=transport.store.tls_state.hostname,
                port=transport.store.tls_state.port,
                con=self._console,
            )
        # certs are passed to the evaluation method. Having them grouped is more readable
        transport = self.evaluate_certificates(
            transport=transport,
        )
        transport = self.evaluate_transports(
            transport=transport,
        )
        # specifics are done, compliance checks are last to be evaluated, do the rest now
        transport = self.evaluate_generic(
            "tls_negotiation",
            transport=transport,
        )
        # compliance checks are last to be evaluated
        transport = self.evaluate_generic(
            "compliance",
            transport=transport,
        )
        for cp in self._checkpoints:
            checkpoint.clear(cp)

        return transport

    def _evaluatation_module(
        self,
        evaluation: dict,
        transport: TLSTransport,
        **kwargs,
    ) -> BaseEvaluationTask | None:
        if any(
            [
                evaluation["group"]
                in self.config["defaults"].get("skip_evaluation_groups", []),
                evaluation["key"]
                in self.config["defaults"].get("skip_evaluations", []),
            ]
        ):
            return
        logger.info(f'{evaluation["group"]}.{evaluation["key"]}')
        try:
            _cls = getattr(
                import_module(
                    f'.evaluations.{evaluation["group"]}.{evaluation["key"]}',
                    package="trivialscan",
                ),
                "EvaluationTask",
            )
        except ModuleNotFoundError:
            log(
                f'[magenta]ModuleNotFoundError[/magenta] {evaluation["group"]}.{evaluation["key"]}',
                hostname=transport.store.tls_state.hostname,
                port=transport.store.tls_state.port,
                con=self._console,
            )
            return None

        return _cls(transport, evaluation, self._shared_config_for_tasks(), **kwargs)

    def _result_data(
        self, result: bool | str | None, task: BaseEvaluationTask, **kwargs
    ) -> tuple[dict, str]:
        label_as = task.metadata["label_as"]
        evaluation_value = "[cyan]EMPTY[/cyan]"
        result_label = "Unknown"
        score = 0
        for anotatation in task.metadata.get("anotate_results", []):
            if isinstance(anotatation["value"], str) and anotatation["value"] == "None":
                anotatation["value"] = None
            if anotatation["value"] is result or anotatation["value"] == result:
                evaluation_value = anotatation["evaluation_value"]
                result_label = anotatation["display_as"]
                score = anotatation["score"]
                break

        substitutions = deepcopy(task.substitution_metadata)
        for substitution in task.metadata.get("substitutions", []):
            value = None
            if hasattr(task.transport.store.tls_state, substitution):
                value = getattr(task.transport.store.tls_state, substitution)
            elif hasattr(task.transport.store, substitution):
                value = getattr(task.transport.store, substitution)
            elif hasattr(task.transport, substitution):
                value = getattr(task.transport, substitution)
            if value:
                substitutions[substitution] = value

        metadata = {**kwargs, **substitutions}
        try:
            label_as = label_as.format(**metadata)
        except KeyError:
            pass
        try:
            evaluation_value = evaluation_value.format(**metadata)
        except KeyError:
            pass
        log_output = " ".join([evaluation_value, label_as])

        return {
            "name": label_as,
            "key": task.metadata["key"],
            "group": task.metadata["group"],
            "cve": task.metadata.get("cve", []),
            "cvss2": task.metadata.get("cvss2", []),
            "cvss3": task.metadata.get("cvss3", []),
            "result": result,
            "result_label": result_label,
            "score": score,
            "references": task.metadata.get("references", []),
            "description": task.metadata["issue"],
            "metadata": metadata,
            "compliance": self._compliance_detail(task.metadata.get("compliance", {})),
        }, log_output

    def _compliance_detail(self, compliance: dict) -> list:
        result = []
        for ctype, _cval in compliance.items():
            for _compliance in _cval:
                cname = f"{ctype} {_compliance['version']}"
                if cname not in self.config:
                    result.append({**{"compliance": ctype}, **_compliance})
                    continue
                if ctype == "PCI DSS":
                    for requirement in _compliance.get("requirements", []) or []:
                        if str(requirement) in self.config[cname]:
                            result.append(
                                {
                                    "compliance": ctype,
                                    "version": str(_compliance["version"]),
                                    "requirement": str(requirement),
                                    "description": self.config[cname][str(requirement)],
                                }
                            )
        return result

    def evaluate_certificates(
        self,
        transport: TLSTransport,
    ):
        use_cp = self.config["defaults"].get("checkpoint")
        checkpoint_name = f"certificates{transport.store.tls_state.hostname}{transport.store.tls_state.port}".encode(
            "utf-8"
        )
        if use_cp and checkpoint.unfinished(checkpoint_name):
            transport.store.evaluations = checkpoint.resume(checkpoint_name)
        else:
            for cert in transport.store.tls_state.certificates:
                if isinstance(cert, LeafCertificate):
                    cert.set_transport(transport)
                cert_data = {
                    "certificate_subject": cert.subject or "",
                    "sha1_fingerprint": cert.sha1_fingerprint,
                    "subject_key_identifier": cert.subject_key_identifier,
                    "authority_key_identifier": cert.authority_key_identifier,
                }
                log(
                    f"[cyan]INFO![/cyan] {cert_data['certificate_subject']}",
                    aside=f"SHA1:{cert.sha1_fingerprint} {transport.store.tls_state.hostname}:{transport.store.tls_state.port}",
                    con=self._console,
                )
                for evaluation in self.config.get("evaluations", []):
                    if evaluation["group"] != "certificate":
                        continue
                    task: BaseEvaluationTask = self._evaluatation_module(
                        evaluation,
                        transport,
                    )
                    if not task:
                        continue
                    result = None
                    try:
                        result = task.evaluate(cert)
                        data, log_output = self._result_data(result, task, **cert_data)
                    except EvaluationNotRelevant:
                        continue
                    except EvaluationNotImplemented:
                        data, _ = self._result_data(None, task, **cert_data)
                        log_output = f"[magenta]Not Implemented[/magenta] {evaluation['label_as']}"
                    except TimeoutError:
                        data, _ = self._result_data(None, task, **cert_data)
                        log_output = f"[cyan]SKIP![/cyan] Slow evaluation detected for {evaluation['label_as']}"
                    except NoLogEvaluation:
                        data, _ = self._result_data(result, task, **cert_data)
                        transport.store.evaluations.append(data)
                        continue
                    transport.store.evaluations.append(data)
                    log(
                        log_output,
                        aside=f"SHA1:{cert.sha1_fingerprint} {transport.store.tls_state.hostname}:{transport.store.tls_state.port}",
                        con=self._console,
                    )
            if use_cp:
                checkpoint.set(checkpoint_name, transport.store.evaluations)
                self._checkpoints.add(checkpoint_name)

        return transport

    def evaluate_generic(
        self,
        group: str,
        transport: TLSTransport,
    ):
        use_cp = self.config["defaults"].get("checkpoint")
        checkpoint_name = f"{group}{transport.store.tls_state.hostname}{transport.store.tls_state.port}".encode(
            "utf-8"
        )
        if use_cp and checkpoint.unfinished(checkpoint_name):
            transport.store.evaluations = checkpoint.resume(checkpoint_name)
        else:
            for evaluation in self.config.get("evaluations", []):
                if evaluation["group"] != group:
                    continue
                task = self._evaluatation_module(
                    evaluation,
                    transport,
                )
                if not task:
                    continue
                try:
                    result = task.evaluate()
                    data, log_output = self._result_data(result, task)
                except EvaluationNotRelevant:
                    continue
                except EvaluationNotImplemented:
                    data, _ = self._result_data(None, task)
                    log_output = (
                        f"[magenta]Not Implemented[/magenta] {evaluation['label_as']}"
                    )
                except TimeoutError:
                    data, _ = self._result_data(None, task)
                    log_output = f"[cyan]SKIP![/cyan] Slow evaluation detected for {evaluation['label_as']}"
                except NoLogEvaluation:
                    data, _ = self._result_data(result, task)
                    transport.store.evaluations.append(data)
                    continue
                transport.store.evaluations.append(data)
                log(
                    log_output,
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    con=self._console,
                )
            if use_cp:
                checkpoint.set(checkpoint_name, transport.store.evaluations)
                self._checkpoints.add(checkpoint_name)

        return transport

    def evaluate_transports(
        self,
        transport: TLSTransport,
    ):
        use_cp = self.config["defaults"].get("checkpoint")
        checkpoint_name = f"transport{transport.store.tls_state.hostname}{transport.store.tls_state.port}".encode(
            "utf-8"
        )
        if use_cp and checkpoint.unfinished(checkpoint_name):
            transport.store.evaluations = checkpoint.resume(checkpoint_name)
        else:
            for evaluation in self.config.get("evaluations", []):
                if evaluation["group"] != "transport":
                    continue
                task = self._evaluatation_module(
                    evaluation,
                    transport,
                )
                if not task:
                    continue
                try:
                    result = task.evaluate()
                    data, log_output = self._result_data(result, task)
                except EvaluationNotRelevant:
                    continue
                except EvaluationNotImplemented:
                    data, _ = self._result_data(None, task)
                    log_output = (
                        f"[magenta]Not Implemented[/magenta] {evaluation['label_as']}"
                    )
                except TimeoutError:
                    data, _ = self._result_data(None, task)
                    log_output = f"[cyan]SKIP![/cyan] Slow evaluation detected for {evaluation['label_as']}"
                except NoLogEvaluation:
                    data, _ = self._result_data(result, task)
                    transport.store.evaluations.append(data)
                    continue
                transport.store.evaluations.append(data)
                log(
                    log_output,
                    hostname=transport.store.tls_state.hostname,
                    port=transport.store.tls_state.port,
                    con=self._console,
                )
            if use_cp:
                checkpoint.set(checkpoint_name, transport.store.evaluations)
                self._checkpoints.add(checkpoint_name)

        return transport


def trivialscan(
    hostname: str,
    port: int = 443,
    http_request_paths: list[str] = ["/"],
    client_certificate: str = None,
    config: dict = None,
    console: Console = None,
    **kwargs,
) -> TLSTransport:
    if config:
        scanner = Trivialscan(console=console, config=config)
    else:
        scanner = Trivialscan(console=console)
    transport = scanner.tls_probe(
        hostname=hostname,
        port=port,
    )
    for request_path in http_request_paths:
        response: HTTPTransport = scanner.http_probe(
            hostname=hostname,
            port=port,
            request_path=request_path,
            client_certificate=client_certificate,
        )
        if response.state:
            transport.store.http_states.append(response.state)
            log(
                f"[cyan]INFO![/cyan] GET {request_path} {response.state.response_status}",
                hostname=hostname,
                port=port,
                con=console,
            )
    return scanner.execute_evaluations(transport)
