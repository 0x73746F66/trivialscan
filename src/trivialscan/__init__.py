import sys
from importlib import import_module
from rich.console import Console
from .config import config
from .transport.insecure import InsecureTransport
from .transport.state import TransportState
from .evaluations import BaseEvaluationTask

__module__ = "trivialscan"

assert sys.version_info >= (3, 10), "Requires Python 3.10 or newer"


def query_hostname(
    hostname: str, port: int = 443, console: Console = None, customs_config: dict = None
) -> tuple[TransportState, list[dict]]:
    use_console = isinstance(console, Console)
    conf = customs_config or config
    transport = InsecureTransport(hostname, port)
    transport.connect_insecure(
        cafiles=conf["defaults"].get("cafiles"),
        use_sni=not conf["defaults"].get("disable_sni"),
    )
    state = transport.get_state()
    evaluations = []
    for evaluation in conf.get("evaluations"):
        _cls = getattr(
            import_module(
                f'.evaluations.{evaluation["group"]}.{evaluation["key"]}',
                package="trivialscan",
            ),
            "EvaluationTask",
        )
        cls: BaseEvaluationTask = _cls(transport, state, evaluation, conf)
        result = cls.evaluate()
        result_label = "Unknown"
        score = 0
        metadata = ""
        if evaluation.get("metadata"):
            for extra in evaluation.get("metadata"):
                value = None
                if hasattr(state, extra.get("key")):
                    value = getattr(state, extra.get("key"))
                if hasattr(transport, extra.get("key")):
                    value = getattr(transport, extra.get("key"))
                if value:
                    metadata += extra.get("format_str") % value
        for anotatation in evaluation["anotate_results"]:
            if anotatation["value"] is result:
                result_label = anotatation["display_as"]
                score = anotatation["score"]
                if use_console:
                    console.print(
                        f'{state.hostname}:{state.port} {anotatation["evaluation_value"]} {evaluation["label_as"]}{metadata}',
                        highlight=False,
                    )
                break
        evaluations.append(
            {
                "name": evaluation["label_as"],
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
            }
        )
        if result is None and use_console:
            console.print(
                f'{state.hostname}:{state.port} [magenta]SKIP![/magenta] {evaluation["label_as"]}',
                highlight=False,
            )

    return state, evaluations
