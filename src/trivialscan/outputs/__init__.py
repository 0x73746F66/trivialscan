import json
from copy import deepcopy
from datetime import datetime
from deepdiff import DeepDiff
from ..config import merge_lists_by_value


def parse_filename(config_value: str, **kwargs) -> str:
    if not has_params(config_value):
        return config_value
    now = datetime.utcnow().replace(microsecond=0)
    return config_value.format(
        **{
            **{
                "date_month": now.month,
                "date_day": now.day,
                "date_year": now.year,
                "date_iso8601": now.isoformat(),
            },
            **kwargs,
        }
    )


def has_params(config_value: str) -> bool:
    return "{" in config_value and "}" in config_value


def track_delta(last: list[dict], current: list[dict]) -> list[dict]:
    exclude_paths = [
        "root['http']['headers']['headers']['date']",
        "root['iterable_item_added']",
        "root['iterable_item_removed']",
        "root['dictionary_item_added']",
        "root['dictionary_item_removed']",
        "root['attribute_added']",
        "root['attribute_removed']",
        "root['type_changes']",
        "root['values_changed']",
        "root['repetition_change']",
    ]
    results = []
    for last_query in last:
        for current_query in current:
            if (
                last_query["transport"]["hostname"]
                != current_query["transport"]["hostname"]
            ):
                continue
            result = deepcopy(current_query)
            ddiff = DeepDiff(
                last_query.get("transport", {}),
                current_query.get("transport", {}),
                ignore_order=True,
                exclude_paths=exclude_paths,
            )
            transport = json.loads(
                ddiff.to_json(default_mapping={datetime: str}).replace(
                    '"root[', '"transport['
                )
            )
            result["transport"] = {**current_query.get("transport", {}), **transport}
            result["evaluations"] = []
            for last_evaluation in last_query.get("evaluations", []):
                for current_evaluation in current_query.get("evaluations", []):
                    if last_evaluation.get("key") != current_evaluation.get("key"):
                        continue
                    ddiff = DeepDiff(
                        last_evaluation, current_evaluation, ignore_order=True
                    )
                    extra = json.loads(
                        ddiff.to_json(default_mapping={datetime: str}).replace(
                            '"root[', '"evaluation['
                        )
                    )
                    result["evaluations"].append({**current_evaluation, **extra})
            results.append(result)
    return merge_lists_by_value(current, results)
