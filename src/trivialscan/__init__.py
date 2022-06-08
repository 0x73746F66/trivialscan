import sys
from importlib import import_module
from copy import deepcopy
from rich.console import Console
from .config import load_config, get_config
from .cli import log
from .transport.insecure import InsecureTransport
from .transport.state import TransportState
from .evaluations import BaseEvaluationTask

__module__ = "trivialscan"

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"
config = get_config(custom_values=load_config())


def evaluate(
    hostname: str,
    port: int = 443,
    evaluations: list = config.get("evaluations"),
    skip_evaluations: list = config["defaults"].get("skip_evaluations", []),
    skip_evaluation_groups: list = config["defaults"].get("skip_evaluation_groups", []),
    use_sni: bool = config["defaults"].get("use_sni"),
    cafiles: str = config["defaults"].get("cafiles"),
    client_certificate: str = None,
    console: Console = None,
    **kwargs,
) -> tuple[TransportState, list[dict]]:
    transport = InsecureTransport(hostname, port)
    if isinstance(client_certificate, str):
        transport.pre_client_authentication_check(client_pem_path=client_certificate)
    transport.connect_insecure(cafiles=cafiles, use_sni=use_sni)
    state = transport.get_state()
    evaluation_results = []
    for evaluation in evaluations:
        label_as = evaluation["label_as"]
        evaluation_value = "[cyan]SKIP![/cyan]"
        result_label = "Unknown"
        score = 0
        if any(
            [
                evaluation["group"] in skip_evaluation_groups,
                evaluation["key"] in skip_evaluations,
            ]
        ):
            log(
                f"{evaluation_value} {label_as}",
                hostname=state.hostname,
                port=state.port,
                con=console,
            )
            continue
        _cls = getattr(
            import_module(
                f'.evaluations.{evaluation["group"]}.{evaluation["key"]}',
                package="trivialscan",
            ),
            "EvaluationTask",
        )
        cls: BaseEvaluationTask = _cls(transport, state, evaluation, config["defaults"])
        result = cls.evaluate()
        for anotatation in evaluation.get("anotate_results", []):
            if anotatation["value"] is result:
                evaluation_value = anotatation["evaluation_value"]
                result_label = anotatation["display_as"]
                score = anotatation["score"]
                break

        substitutions = deepcopy(cls.substitution_metadata)
        for substitution in evaluation.get("substitutions", []):
            value = None
            if hasattr(state, substitution):
                value = getattr(state, substitution)
            if hasattr(transport, substitution):
                value = getattr(transport, substitution)
            if value:
                substitutions[substitution] = value
        if substitutions:
            label_as = label_as.format(**substitutions)
            evaluation_value = evaluation_value.format(**substitutions)
        log(
            f"{evaluation_value} {label_as}",
            hostname=state.hostname,
            port=state.port,
            con=console,
        )
        compliance = []
        for ctype, _cval in evaluation.get("compliance", {}).items():
            for _compliance in _cval:
                cname = f"{ctype} {_compliance['version']}"
                if cname not in config:
                    compliance.append({**{"compliance": ctype}, **_compliance})
                    continue
                if ctype == "PCI DSS":
                    for requirement in _compliance.get("requirements", []) or []:
                        if str(requirement) in config[cname]:
                            compliance.append(
                                {
                                    "compliance": ctype,
                                    "version": str(_compliance["version"]),
                                    "requirement": str(requirement),
                                    "description": config[cname][str(requirement)],
                                }
                            )

        evaluation_results.append(
            {
                "name": label_as,
                "key": evaluation["key"],
                "group": evaluation["group"],
                "cve": evaluation.get("cve", []),
                "cvss2": evaluation.get("cvss2", []),
                "cvss3": evaluation.get("cvss3", []),
                "result": result,
                "result_label": result_label,
                "score": score,
                "references": evaluation.get("references", []),
                "description": evaluation["issue"],
                "metadata": substitutions,
                "compliance": compliance,
            }
        )

    return state, evaluation_results
