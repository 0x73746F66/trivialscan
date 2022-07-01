from asyncio.log import logger
import sys
from importlib import import_module
from copy import deepcopy
from rich.console import Console
from trivialscan.transport import Transport
from .config import load_config, get_config
from .util import TimeoutError
from .cli import log
from .transport.insecure import InsecureTransport
from .transport.state import TransportState
from .certificate import LeafCertificate
from .exceptions import EvaluationNotImplemented, EvaluationNotRelevant, NoLogEvaluation
from .evaluations import BaseEvaluationTask

__module__ = "trivialscan"

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
config = get_config(custom_values=load_config())


def evaluate(
    hostname: str,
    port: int = 443,
    http_request_path: str = "/",
    evaluations: list = config.get("evaluations"),
    skip_evaluations: list = config["defaults"].get("skip_evaluations", []),
    skip_evaluation_groups: list = config["defaults"].get("skip_evaluation_groups", []),
    use_sni: bool = config["defaults"].get("use_sni"),
    cafiles: str = config["defaults"].get("cafiles"),
    client_certificate: str = None,
    console: Console = None,
    **kwargs,
) -> tuple[TransportState, list[dict]]:
    evaluation_results = []
    transport = InsecureTransport(hostname, port)
    if isinstance(client_certificate, str):
        transport.pre_client_authentication_check(client_pem_path=client_certificate)
    transport.connect_insecure(cafiles=cafiles, use_sni=use_sni)
    state = transport.state
    log(
        f"[cyan]INTO![/cyan] Negotiated {state.negotiated_protocol} {state.peer_address}",
        hostname=state.hostname,
        port=state.port,
        con=console,
    )
    host_data = {
        "hostname": state.hostname,
        "port": state.port,
        "peer_address": state.peer_address,
    }
    # certs are passed to the evaluation method. Having them grouped is more readable
    for cert in state.certificates:
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
            aside=f"SHA1:{cert.sha1_fingerprint} {state.hostname}:{state.port}",
            con=console,
        )
        for evaluation in evaluations:
            if evaluation["group"] != "certificate":
                continue
            task = _evaluatation_module(
                evaluation,
                transport,
                skip_evaluations,
                skip_evaluation_groups,
                con=console,
            )
            if not task:
                continue
            result = None
            try:
                result = task.evaluate(cert)
                data, log_output = _result_data(result, task, **cert_data, **host_data)
            except EvaluationNotRelevant:
                continue
            except EvaluationNotImplemented:
                data, _ = _result_data(None, task, **cert_data, **host_data)
                log_output = (
                    f"[magenta]Not Implemented[/magenta] {evaluation['label_as']}"
                )
            except TimeoutError:
                data, _ = _result_data(None, task, **cert_data, **host_data)
                log_output = f"[cyan]SKIP![/INFO] Slow evaluation detected for {evaluation['label_as']}"
            except NoLogEvaluation:
                data, _ = _result_data(result, task, **cert_data, **host_data)
                evaluation_results.append(data)
                continue
            evaluation_results.append(data)
            log(
                log_output,
                aside=f"SHA1:{cert.sha1_fingerprint} {state.hostname}:{state.port}",
                con=console,
            )

    # certificates are done, compliance checks are last to be evaluated
    for evaluation in evaluations:
        if evaluation["group"] in ["certificate", "compliance"]:
            continue
        task = _evaluatation_module(
            evaluation, transport, skip_evaluations, skip_evaluation_groups, con=console
        )
        if evaluation["group"] == "transport":
            response = task.do_request(http_request_path)
            log_line = None
            if not response:
                log_line = f"[cyan]SKIP![/cyan] (Missing HTTP Response) {evaluation['label_as']}"
            if task.skip:
                log_line = f"[cyan]SKIP![/cyan] (robots.txt) {evaluation['label_as']}"
            if log_line:
                log(
                    log_line,
                    hostname=state.hostname,
                    port=state.port,
                    con=console,
                )
                continue
        if not task:
            continue
        try:
            result = task.evaluate()
            data, log_output = _result_data(result, task, **host_data)
        except EvaluationNotRelevant:
            continue
        except EvaluationNotImplemented:
            data, _ = _result_data(None, task, **cert_data, **host_data)
            log_output = f"[magenta]Not Implemented[/magenta] {evaluation['label_as']}"
        except TimeoutError:
            data, _ = _result_data(None, task, **cert_data, **host_data)
            log_output = f"[cyan]SKIP![/INFO] Slow evaluation detected for {evaluation['label_as']}"
        except NoLogEvaluation:
            data, _ = _result_data(result, task, **host_data)
            evaluation_results.append(data)
            continue
        evaluation_results.append(data)
        log(
            log_output,
            hostname=state.hostname,
            port=state.port,
            con=console,
        )

    # compliance checks are last to be evaluated
    for evaluation in evaluations:
        if evaluation["group"] != "compliance":
            continue
        task = _evaluatation_module(
            evaluation, transport, skip_evaluations, skip_evaluation_groups, con=console
        )
        if not task:
            continue
        try:
            result = task.evaluate()
            data, log_output = _result_data(result, task, **host_data)
        except EvaluationNotRelevant:
            continue
        except EvaluationNotImplemented:
            data, _ = _result_data(None, task, **cert_data, **host_data)
            log_output = f"[magenta]Not Implemented[/magenta] {evaluation['label_as']}"
        except TimeoutError:
            data, _ = _result_data(None, task, **cert_data, **host_data)
            log_output = f"[cyan]SKIP![/INFO] Slow evaluation detected for {evaluation['label_as']}"
        except NoLogEvaluation:
            data, _ = _result_data(result, task, **host_data)
            evaluation_results.append(data)
            continue
        evaluation_results.append(data)
        log(
            log_output,
            hostname=state.hostname,
            port=state.port,
            con=console,
        )

    return transport, evaluation_results


def _evaluatation_module(
    evaluation: dict,
    transport: Transport,
    skip_evaluations: list,
    skip_evaluation_groups: list,
    con: Console = None,
    **kwargs,
) -> BaseEvaluationTask | None:
    if any(
        [
            evaluation["group"] in skip_evaluation_groups,
            evaluation["key"] in skip_evaluations,
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
            hostname=transport.state.hostname,
            port=transport.state.port,
            con=con,
        )
        return None

    return _cls(transport, evaluation, config["defaults"], **kwargs)


def _result_data(
    result: bool | str | None, task: BaseEvaluationTask, **kwargs
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
        if hasattr(task.state, substitution):
            value = getattr(task.state, substitution)
        if hasattr(task.transport, substitution):
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
        "compliance": _compliance_detail(task.metadata.get("compliance", {})),
    }, log_output


def _compliance_detail(compliance: dict) -> list:
    result = []
    for ctype, _cval in compliance.items():
        for _compliance in _cval:
            cname = f"{ctype} {_compliance['version']}"
            if cname not in config:
                result.append({**{"compliance": ctype}, **_compliance})
                continue
            if ctype == "PCI DSS":
                for requirement in _compliance.get("requirements", []) or []:
                    if str(requirement) in config[cname]:
                        result.append(
                            {
                                "compliance": ctype,
                                "version": str(_compliance["version"]),
                                "requirement": str(requirement),
                                "description": config[cname][str(requirement)],
                            }
                        )
    return result
