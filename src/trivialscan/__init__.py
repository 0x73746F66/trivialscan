import sys
import logging
from os import path
from importlib import import_module
from copy import deepcopy
from dataclasses import asdict
from typing import Union

from rich.console import Console

from . import cli, constants
from .config import load_config, get_config
from .exceptions import (
    EvaluationNotRelevant,
    NoLogEvaluation,
    TransportError,
)
from .transport import TLSTransport, HTTPTransport
from .transport.insecure import InsecureTransport
from .evaluations import BaseEvaluationTask, EvaluationResult
from .certificate import LeafCertificate
from .outputs import checkpoint

__module__ = "trivialscan"

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"
logger = logging.getLogger(__name__)


class Trivialscan:
    _checkpoints: set = set()
    _console: Console = None
    _transport: TLSTransport = None
    config: dict = get_config(custom_values=load_config())

    def __init__(self, console: Console = None, **kwargs) -> None:
        self.config = kwargs.get("config", self.config)
        self._console = console
        self._use_icons = any(
            n.get("type") == "console" and n.get("use_icons")
            for n in self.config.get("outputs", [])
        )
        self._show_probe = not self.config["defaults"].get("hide_probe_info", False)
        self._use_cp = self.config["defaults"].get("checkpoint")
        self._resume_cp = self.config["defaults"].get("resume_checkpoint")

    def tls_probe(
        self,
        hostname: str,
        port: int = 443,
        client_certificate: str = None,
    ) -> bool:
        try:
            if self._show_probe:
                cli.outputln(
                    "Protocol SSL/TLS",
                    hostname=hostname,
                    port=port,
                    result_text="PROBE",
                    result_icon=":globe_with_meridians:",
                    con=self._console,
                    use_icons=self._use_icons,
                )
            self._transport = InsecureTransport(hostname, port)
            if isinstance(client_certificate, str):
                self._transport.pre_client_authentication_check(
                    client_pem_path=client_certificate,
                    tmp_path_prefix=self.config["defaults"].get(
                        "tmp_path_prefix", "/tmp"
                    ),
                )
            self._transport.connect_insecure(
                cafiles=self.config["defaults"].get("cafiles"),
                use_sni=self.config["defaults"].get("use_sni"),
            )
            if self._use_cp:
                certs = []
                for cert in self._transport.store.tls_state.certificates:
                    if isinstance(cert, LeafCertificate):
                        cert.set_transport(self._transport)
                    certs.append(cert)
                self._transport.store.tls_state.certificates = certs
        except TransportError as err:
            self._transport.store.error = (type(err).__name__, str(err))
            cli.failln(
                err,
                result_text=type(err).__name__,
                hostname=hostname,
                port=port,
                con=self._console,
                use_icons=self._use_icons,
            )
        if self._transport.store.tls_state.negotiated_protocol:
            cli.outputln(
                f"Negotiated {self._transport.store.tls_state.negotiated_protocol} {self._transport.store.tls_state.peer_address}",
                hostname=self._transport.store.tls_state.hostname,
                port=self._transport.store.tls_state.port,
                con=self._console,
                use_icons=self._use_icons,
            )
            return True

        return False

    def http_probe(
        self,
        hostname: str,
        request_path: str,
        port: int = 443,
        client_certificate: str = None,
        tmp_path_prefix: str = config["defaults"].get("tmp_path_prefix", "/tmp"),
    ) -> HTTPTransport:
        if not isinstance(self._transport, TLSTransport):
            raise RuntimeError
        transport = HTTPTransport(
            hostname=hostname,
            port=port,
            tmp_path_prefix=tmp_path_prefix,
        )
        if self._show_probe:
            cli.outputln(
                "Protocol: HTTP/1 HTTP/1.1",
                hostname=self._transport.store.tls_state.hostname,
                port=self._transport.store.tls_state.port,
                result_text="PROBE",
                result_icon=":globe_with_meridians:",
                con=self._console,
                use_icons=self._use_icons,
            )
        if transport.do_request(
            http_request_path=request_path,
            cafiles=self.config["defaults"].get("cafiles"),
            client_certificate=client_certificate,
        ):
            cli.outputln(
                f"GET {request_path} {transport.state.response_status}",
                hostname=hostname,
                port=port,
                con=self._console,
                use_icons=self._use_icons,
            )
        if transport.state:
            self._transport.store.http_states.append(transport.state)

        return transport

    def _shared_config_for_tasks(self) -> dict:
        return {
            "use_sni": self.config["defaults"].get("use_sni"),
            "cafiles": self.config["defaults"].get("cafiles"),
            "tmp_path_prefix": self.config["defaults"].get("tmp_path_prefix"),
        }

    def execute_evaluations(self):
        if not isinstance(self._transport, TLSTransport):
            raise RuntimeError
        # certs are passed to the evaluation method. Having them grouped is more readable
        self.evaluate_certificates()
        self.evaluate_transports()
        # specifics are done, compliance checks are last to be evaluated, do the rest now
        self.evaluate_generic("tls_negotiation")
        # compliance checks are last to be evaluated
        self.evaluate_generic("compliance")
        for cp in self._checkpoints:
            checkpoint.clear(cp)

        return self._transport

    def _evaluatation_module(
        self,
        evaluation: dict,
        **kwargs,
    ) -> Union[BaseEvaluationTask, None]:
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
            cli.outputln(
                f'{evaluation["group"]}.{evaluation["key"]}',
                hostname=self._transport.store.tls_state.hostname,
                port=self._transport.store.tls_state.port,
                result_color="magenta",
                result_text="ModuleNotFoundError",
                con=self._console,
                use_icons=self._use_icons,
            )
            return None

        return _cls(
            self._transport, evaluation, self._shared_config_for_tasks(), **kwargs
        )

    def _result_data(
        self, result_value: Union[bool, str, None], task: BaseEvaluationTask, **kwargs
    ) -> EvaluationResult:
        data = {
            "rule_id": task.metadata["rule_id"],
            "group_id": task.metadata["group_id"],
            "name": task.metadata["label_as"],
            "key": task.metadata["key"],
            "group": task.metadata["group"],
            "cve": task.metadata.get("cve", []),
            "cvss2": task.metadata.get("cvss2", []),
            "cvss3": task.metadata.get("cvss3", []),
            "result_value": result_value,
            "result_text": constants.RESULT_LEVEL_INFO_DEFAULT,
            "result_level": constants.RESULT_LEVEL_INFO,
            "result_label": "Not Implemented",
            "score": 0,
            "references": task.metadata.get("references", []),
            "description": task.metadata["issue"],
            "metadata": {},
            "compliance": self._compliance_detail(task.metadata.get("compliance", {})),
            "threats": self._threats_detail(task.metadata.get("threats", {})),
        }
        for anotatation in task.metadata.get("anotate_results", []):
            if (
                isinstance(anotatation["result_value"], str)
                and anotatation["result_value"] == "None"
            ):
                anotatation["result_value"] = None
            if (
                anotatation["result_value"] is result_value
                or anotatation["result_value"] == result_value
            ):
                data["result_level"] = anotatation.get(
                    "result_level", constants.RESULT_LEVEL_INFO
                )
                data["result_text"] = anotatation.get(
                    "result_text",
                    constants.DEFAULT_MAP.get(
                        data["result_level"], constants.RESULT_LEVEL_INFO_DEFAULT
                    ),
                )
                data["result_label"] = anotatation["display_as"]
                data["score"] = anotatation["score"]
                break

        substitutions = deepcopy(task.substitution_metadata)
        for substitution in task.metadata.get("substitutions", []):
            substitution_value = None
            if hasattr(task.transport.store.tls_state, substitution):
                substitution_value = getattr(
                    task.transport.store.tls_state, substitution
                )
            elif hasattr(task.transport.store, substitution):
                substitution_value = getattr(task.transport.store, substitution)
            elif hasattr(task.transport, substitution):
                substitution_value = getattr(task.transport, substitution)
            if substitution_value:
                substitutions[substitution] = substitution_value

        data["metadata"] = {**kwargs, **substitutions}
        try:
            data["name"] = data["name"].format(**data["metadata"])
        except KeyError:
            pass
        try:
            data["result_label"] = data["result_label"].format(**data["metadata"])
        except KeyError:
            pass

        return EvaluationResult(**data)

    def _threats_detail(self, threats: dict) -> list:
        result = []
        if not threats:
            return result
        for ctype, _cval in threats.items():
            for _standard in _cval:
                cname = f"{ctype} {_standard['version']}"
                if cname not in self.config:
                    result.append({**{"standard": ctype}, **_standard})
                    continue
                if ctype == "MITRE ATT&CK":
                    for conf_tactic in self.config[cname]["tactics"]:
                        if conf_tactic["id"] in _standard["tactics"]:
                            result.append(
                                {
                                    "standard": ctype,
                                    "version": str(_standard["version"]),
                                    "tactic_id": str(conf_tactic["id"]),
                                    "tactic_url": path.join(
                                        self.config[cname]["tactics_base_url"],
                                        conf_tactic["id"],
                                    ),
                                    "tactic": conf_tactic["name"],
                                    "description": conf_tactic["description"],
                                }
                            )
                    for conf_data_sources in self.config[cname]["data_sources"]:
                        if conf_data_sources["id"] in _standard["data_sources"]:
                            result.append(
                                {
                                    "standard": ctype,
                                    "version": str(_standard["version"]),
                                    "data_source_id": str(conf_data_sources["id"]),
                                    "data_source_url": path.join(
                                        self.config[cname]["data_sources_base_url"],
                                        conf_data_sources["id"],
                                    ),
                                    "data_source": conf_data_sources["name"],
                                    "description": conf_data_sources["description"],
                                }
                            )
                    for conf_techniques in self.config[cname]["techniques"]:
                        if conf_techniques["id"] in _standard["techniques"]:
                            result.append(
                                {
                                    "standard": ctype,
                                    "version": str(_standard["version"]),
                                    "technique_id": str(conf_techniques["id"]),
                                    "technique_url": path.join(
                                        self.config[cname]["techniques_base_url"],
                                        conf_techniques["id"],
                                    ),
                                    "technique": conf_techniques["name"],
                                    "description": conf_techniques["description"],
                                }
                            )
                        for sub_technique in _standard.get("sub_techniques", []) or []:
                            if conf_techniques["id"] != sub_technique["parent"]:
                                continue
                            for conf_sub_technique in (
                                conf_techniques.get("sub_techniques", []) or []
                            ):
                                if conf_sub_technique["id"] == sub_technique["id"]:
                                    result.append(
                                        {
                                            "standard": ctype,
                                            "version": str(_standard["version"]),
                                            "technique_id": str(conf_techniques["id"]),
                                            "technique_url": path.join(
                                                self.config[cname][
                                                    "techniques_base_url"
                                                ],
                                                conf_techniques["id"],
                                            ),
                                            "technique": conf_techniques["name"],
                                            "technique_description": conf_techniques[
                                                "description"
                                            ],
                                            "sub_technique_id": str(
                                                sub_technique["id"]
                                            ),
                                            "sub_technique_url": path.join(
                                                self.config[cname][
                                                    "techniques_base_url"
                                                ],
                                                conf_techniques["id"],
                                                sub_technique["id"],
                                            ),
                                            "sub_technique": conf_sub_technique["name"],
                                            "sub_technique_description": conf_sub_technique[
                                                "description"
                                            ],
                                        }
                                    )
        return result

    def _compliance_detail(self, compliance: dict) -> list:
        result = []
        if not compliance:
            return result
        for ctype, _cval in compliance.items():
            for _compliance in _cval:
                cname = f"{ctype} {_compliance['version']}"
                if cname not in self.config:
                    result.append({**{"compliance": ctype}, **_compliance})
                    continue
                if ctype == "PCI DSS":
                    for requirement in _compliance.get("requirements", []) or []:
                        if str(requirement) in self.config[cname]["requirements"]:
                            result.append(
                                {
                                    "compliance": ctype,
                                    "version": str(_compliance["version"]),
                                    "requirement": str(requirement),
                                    "description": self.config[cname]["requirements"][
                                        str(requirement)
                                    ],
                                }
                            )
                        else:
                            result.append({**{"compliance": ctype}, **_compliance})

        return result

    def evaluate_certificates(self):
        if not isinstance(self._transport, TLSTransport):
            raise RuntimeError
        checkpoint_name = f"certificates{self._transport.store.tls_state.hostname}{self._transport.store.tls_state.port}".encode(
            "utf-8"
        )
        if self._resume_cp and checkpoint.unfinished(checkpoint_name):
            cli.outputln(
                "Attempting to resume last scan from saved certificates checkpoint",
                hostname=self._transport.store.tls_state.hostname,
                port=self._transport.store.tls_state.port,
                con=self._console,
                use_icons=self._use_icons,
            )
            self._transport.store.evaluations = checkpoint.resume(checkpoint_name)
            self._checkpoints.add(checkpoint_name)
            return
        for cert in self._transport.store.tls_state.certificates:
            cert_data = {
                "certificate_subject": cert.subject or "",
                "sha1_fingerprint": cert.sha1_fingerprint,
                "subject_key_identifier": cert.subject_key_identifier,
                "authority_key_identifier": cert.authority_key_identifier,
            }
            if isinstance(cert, LeafCertificate):
                cert.set_transport(self._transport)
            cli.outputln(
                cert_data["certificate_subject"],
                aside=f"SHA1:{cert.sha1_fingerprint} {self._transport.store.tls_state.hostname}:{self._transport.store.tls_state.port}",
                con=self._console,
                use_icons=self._use_icons,
            )
            for evaluation in self.config.get("evaluations", []):
                if evaluation["group"] != "certificate":
                    continue
                task: BaseEvaluationTask = self._evaluatation_module(
                    evaluation,
                )
                if not task:
                    continue
                if self._show_probe and task.probe_info:
                    cli.outputln(
                        task.probe_info,
                        hostname=self._transport.store.tls_state.hostname,
                        port=self._transport.store.tls_state.port,
                        result_text="PROBE",
                        result_icon=":globe_with_meridians:",
                        con=self._console,
                        use_icons=self._use_icons,
                    )
                result = None
                try:
                    result = task.evaluate(cert)
                    evaluation_result = self._result_data(result, task, **cert_data)
                except EvaluationNotRelevant:
                    continue
                except NotImplementedError:
                    evaluation_result = self._result_data(None, task, **cert_data)
                    evaluation_result.result_color = "magenta"
                    evaluation_result.result_text = "SKIP!"
                except TimeoutError:
                    evaluation_result = self._result_data(None, task, **cert_data)
                    evaluation_result.result_color = "magenta"
                    evaluation_result.result_text = "SKIP!"
                    evaluation_result.result_label = "Timeout"
                except NoLogEvaluation:
                    evaluation_result = self._result_data(result, task, **cert_data)
                    evaluation_result.result_label = "No evaluation result"
                    self._transport.store.evaluations.append(evaluation_result)
                    continue
                self._transport.store.evaluations.append(evaluation_result)
                cli.outputln(
                    f"{evaluation_result.group_id}.{evaluation_result.rule_id} {evaluation_result.name}",
                    bold_result=True,
                    aside=f"SHA1:{cert.sha1_fingerprint} {self._transport.store.tls_state.hostname}:{self._transport.store.tls_state.port}",
                    con=self._console,
                    use_icons=self._use_icons,
                    **asdict(evaluation_result),
                )
        if self._use_cp:
            checkpoint.mark(checkpoint_name, self._transport.store.evaluations)
            self._checkpoints.add(checkpoint_name)

    def evaluate_generic(self, group: str):
        if not isinstance(self._transport, TLSTransport):
            raise RuntimeError
        checkpoint_name = f"{group}{self._transport.store.tls_state.hostname}{self._transport.store.tls_state.port}".encode(
            "utf-8"
        )
        if self._resume_cp and checkpoint.unfinished(checkpoint_name):
            cli.outputln(
                f"Attempting to resume last scan from saved '{group}' checkpoint",
                hostname=self._transport.store.tls_state.hostname,
                port=self._transport.store.tls_state.port,
                con=self._console,
                use_icons=self._use_icons,
            )
            self._transport.store.evaluations = checkpoint.resume(checkpoint_name)
            self._checkpoints.add(checkpoint_name)
        else:
            for evaluation in self.config.get("evaluations", []):
                if evaluation["group"] != group:
                    continue
                task = self._evaluatation_module(
                    evaluation,
                )
                if not task:
                    continue
                if self._show_probe and task.probe_info:
                    cli.outputln(
                        task.probe_info,
                        hostname=self._transport.store.tls_state.hostname,
                        port=self._transport.store.tls_state.port,
                        result_text="PROBE",
                        result_icon=":globe_with_meridians:",
                        con=self._console,
                        use_icons=self._use_icons,
                    )
                try:
                    result = task.evaluate()
                    evaluation_result = self._result_data(result, task)
                except EvaluationNotRelevant:
                    continue
                except NotImplementedError:
                    evaluation_result = self._result_data(None, task)
                    evaluation_result.result_color = "magenta"
                    evaluation_result.result_text = "SKIP!"
                except TimeoutError:
                    evaluation_result = self._result_data(None, task)
                    evaluation_result.result_color = "magenta"
                    evaluation_result.result_text = "SKIP!"
                    evaluation_result.result_label = "Timeout"
                except NoLogEvaluation:
                    evaluation_result = self._result_data(result, task)
                    self._transport.store.evaluations.append(evaluation_result)
                    continue
                self._transport.store.evaluations.append(evaluation_result)
                cli.outputln(
                    f"{evaluation_result.group_id}.{evaluation_result.rule_id} {evaluation_result.name}",
                    bold_result=True,
                    hostname=self._transport.store.tls_state.hostname,
                    port=self._transport.store.tls_state.port,
                    con=self._console,
                    use_icons=self._use_icons,
                    **asdict(evaluation_result),
                )
            if self._use_cp:
                checkpoint.mark(checkpoint_name, self._transport.store.evaluations)
                self._checkpoints.add(checkpoint_name)

    def evaluate_transports(self):
        if not isinstance(self._transport, TLSTransport):
            raise RuntimeError
        checkpoint_name = f"transport{self._transport.store.tls_state.hostname}{self._transport.store.tls_state.port}".encode(
            "utf-8"
        )
        if self._resume_cp and checkpoint.unfinished(checkpoint_name):
            cli.outputln(
                "Attempting to resume last scan from saved transport protoccol checkpoint",
                hostname=self._transport.store.tls_state.hostname,
                port=self._transport.store.tls_state.port,
                con=self._console,
                use_icons=self._use_icons,
            )
            self._transport.store.evaluations = checkpoint.resume(checkpoint_name)
            self._checkpoints.add(checkpoint_name)
            return
        for evaluation in self.config.get("evaluations", []):
            if evaluation["group"] != "transport":
                continue
            task = self._evaluatation_module(
                evaluation,
            )
            if not task:
                continue
            if self._show_probe and task.probe_info:
                cli.outputln(
                    task.probe_info,
                    hostname=self._transport.store.tls_state.hostname,
                    port=self._transport.store.tls_state.port,
                    result_text="PROBE",
                    result_icon=":globe_with_meridians:",
                    con=self._console,
                    use_icons=self._use_icons,
                )
            try:
                result = task.evaluate()
                evaluation_result = self._result_data(result, task)
            except EvaluationNotRelevant:
                continue
            except NotImplementedError:
                evaluation_result = self._result_data(None, task)
                evaluation_result.result_color = "magenta"
                evaluation_result.result_text = "SKIP!"
            except TimeoutError:
                evaluation_result = self._result_data(None, task)
                evaluation_result.result_color = "magenta"
                evaluation_result.result_text = "SKIP!"
                evaluation_result.result_label = "Timeout"
            except NoLogEvaluation:
                evaluation_result = self._result_data(result, task)
                self._transport.store.evaluations.append(evaluation_result)
                continue
            self._transport.store.evaluations.append(evaluation_result)
            cli.outputln(
                f"{evaluation_result.group_id}.{evaluation_result.rule_id} {evaluation_result.name}",
                bold_result=True,
                hostname=self._transport.store.tls_state.hostname,
                port=self._transport.store.tls_state.port,
                con=self._console,
                use_icons=self._use_icons,
                **asdict(evaluation_result),
            )
        if self._use_cp:
            checkpoint.mark(checkpoint_name, self._transport.store.evaluations)
            self._checkpoints.add(checkpoint_name)


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
        scanner = Trivialscan(console=console, config=config, **kwargs)
    else:
        scanner = Trivialscan(console=console, **kwargs)
    if not scanner.tls_probe(
        hostname=hostname,
        port=port,
    ):
        return scanner._transport  # pylint: disable=protected-access
    for request_path in http_request_paths:
        scanner.http_probe(
            hostname=hostname,
            port=port,
            request_path=request_path,
            client_certificate=client_certificate,
        )
    return scanner.execute_evaluations()
