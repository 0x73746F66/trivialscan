import logging
from os import path
from glob import glob
from pathlib import Path
from copy import deepcopy
from urllib.parse import urlparse
from typing import Union

import validators
import yaml

__module__ = "trivialscan.config"

logger = logging.getLogger(__name__)
DEFAULT_CONFIG = ".trivialscan-config.yaml"
CONFIG_PATH = f"{path.expanduser('~')}/.config/trivial"


def force_keys_as_str(self, node, deep=False):
    data = self.old_construct_mapping(node, deep)
    return {
        (str(key) if isinstance(key, (int, float)) else key): data[key] for key in data
    }


yaml.SafeLoader.old_construct_mapping = yaml.SafeLoader.construct_mapping
yaml.SafeLoader.construct_mapping = force_keys_as_str


def _deep_merge(*args) -> dict:
    assert len(args) >= 2, "_deep_merge requires at least two dicts to merge"
    result = deepcopy(args[0])
    if not isinstance(result, dict):
        raise AttributeError(
            f"_deep_merge only takes dict arguments, got {type(result)} {result}"
        )
    for merge_dict in args[1:]:
        if not isinstance(merge_dict, dict):
            raise AttributeError(
                f"_deep_merge only takes dict arguments, got {type(merge_dict)} {merge_dict}"
            )
        for key, merge_val in merge_dict.items():
            result_val = result.get(key)
            if isinstance(result_val, dict) and isinstance(merge_val, dict):
                result[key] = _deep_merge(result_val, merge_val)
            else:
                result[key] = deepcopy(merge_val)
    return result


def _evaluation_merge(key: str, item1: dict, item2: dict) -> dict:
    if not isinstance(key, str):
        raise AttributeError(f"_evaluation_merge key should be str, got {type(key)}")
    if item1[key] != item2[key]:
        raise AttributeError(
            f"_evaluation_merge key should match both items, got {item1[key]} {item2[key]}"
        )
    return_dict = deepcopy(item1)
    if not isinstance(item1, dict) or not isinstance(item2, dict):
        raise AttributeError(
            f"_evaluation_merge only takes dict arguments, got {type(item1)} {type(item2)}"
        )
    if item2.get("cve"):
        return_dict["cve"] = list({*item1.get("cve", []), *item2.get("cve", [])})
    if item2.get("substitutions"):
        return_dict["substitutions"] = list(
            {*item1.get("substitutions", []), *item2.get("substitutions", [])}
        )
    if item2.get("references"):
        return_dict["references"] = _merge_2_lists_of_dicts(
            item1.get("references", []), item2.get("references", []), unique_key="name"
        )
    if item2.get("anotate_results"):
        return_dict["anotate_results"] = _merge_2_lists_of_dicts(
            item1.get("anotate_results", []),
            item2.get("anotate_results", []),
            unique_key="value",
        )
    update_props = ["group", "label_as", "issue", "cvss2", "cvss3"]
    for prop in update_props:
        return_dict[prop] = item2.get(prop, item1.get(prop))

    return return_dict


def _default_dict_merger(key: str, item1: dict, item2: dict) -> dict:
    merged = deepcopy(item1)
    merged.update(item2)
    return merged


def merge_lists_by_value(
    *args, unique_key: str = "key", merge_fn=_default_dict_merger
) -> list:
    assert len(args) >= 2, "merge_lists_by_value requires at least two lists to merge"
    result = deepcopy(args[0])
    if not isinstance(result, list):
        raise AttributeError("merge_lists_by_value only takes list arguments")
    step = 1
    while step < len(args):
        merge_list = deepcopy(args[step])
        if not isinstance(merge_list, list):
            raise AttributeError("merge_lists_by_value only takes list arguments")
        if not result:
            result = merge_list
            step += 1
            continue
        if not merge_list:
            step += 1
            continue

        result = _merge_2_lists_of_dicts(
            result, merge_list, unique_key=unique_key, merge_fn=merge_fn
        )
        step += 1

    return list(filter(None, result))


def _merge_2_lists_of_dicts(
    list1: list, list2: list, unique_key: str = "key", merge_fn=_default_dict_merger
) -> list:
    if not isinstance(list1, list) or not isinstance(list2, list):
        raise AttributeError("_merge_2_lists_of_dicts only takes list arguments")
    result = []
    index = set()
    for item1 in list1:
        for item2 in list2:
            if item1.get(unique_key) == item2.get(unique_key):
                index.add(item1.get(unique_key))
                merged = merge_fn(unique_key, item1, item2)
                result.append(merged)
    for item1 in list1:
        if item1.get(unique_key) not in index:
            index.add(item1.get(unique_key))
            result.append(item1)
    for item2 in list2:
        if item2.get(unique_key) not in index:
            result.append(item2)

    return result


def _validate_config(combined_config: dict) -> dict:
    http_request_path = combined_config["defaults"].get("http_request_path", "/")
    skip_evaluations = combined_config["defaults"].get("skip_evaluations", [])
    skip_evaluation_groups = combined_config["defaults"].get(
        "skip_evaluation_groups", []
    )
    targets = []
    for target in combined_config.get("targets", []):
        hostname = target.get("hostname")
        if not hostname or not isinstance(hostname, str):
            raise AttributeError("Missing hostname")
        if not hostname.startswith("http"):
            hostname = f"https://{hostname}"
        parsed = urlparse(hostname)
        if validators.domain(parsed.hostname) is not True:
            raise AttributeError(
                f"URL {hostname} hostname {parsed.hostname} is invalid"
            )
        if isinstance(target.get("port"), str):
            target["port"] = int(target.get("port"))
        if (
            target.get("port") is None or target.get("port") == 0
        ):  # falsey type coercion
            target["port"] = 443
        target["http_request_paths"] = list(
            set(
                [
                    http_request_path,
                    *target.get("http_request_paths", []),
                ]
            )
        )
        target["skip_evaluations"] = [
            *skip_evaluations,
            *target.get("skip_evaluations", []),
        ]
        target["skip_evaluation_groups"] = [
            *skip_evaluation_groups,
            *target.get("skip_evaluation_groups", []),
        ]
        targets.append(target)
    combined_config["targets"] = targets

    return combined_config


def combine_configs(user_conf: dict, custom_conf: dict) -> dict:
    default_values = default_config()
    ret_config = {
        "account_name": custom_conf.get(
            "account_name",
            user_conf.get("account_name", default_values.get("account_name", None)),
        ),
        "client_name": custom_conf.get(
            "client_name",
            user_conf.get("client_name", default_values.get("client_name", None)),
        ),
        "project_name": custom_conf.get(
            "project_name",
            user_conf.get("project_name", default_values.get("project_name", None)),
        ),
        "defaults": {
            **default_values.get("defaults", {}),
            **user_conf.get("defaults", {}),
            **custom_conf.get("defaults", {}),
        },
        "PCI DSS 4.0": {
            **default_values.get("PCI DSS 4.0", {}),
            **user_conf.get("PCI DSS 4.0", {}),
            **custom_conf.get("PCI DSS 4.0", {}),
        },
        "PCI DSS 3.2.1": {
            **default_values.get("PCI DSS 3.2.1", {}),
            **user_conf.get("PCI DSS 3.2.1", {}),
            **custom_conf.get("PCI DSS 3.2.1", {}),
        },
        "MITRE ATT&CK 11.2": {
            **default_values.get("MITRE ATT&CK 11.2", {}),
            **user_conf.get("MITRE ATT&CK 11.2", {}),
            **custom_conf.get("MITRE ATT&CK 11.2", {}),
        },
    }
    outputs = custom_conf.get("outputs", [])
    outputs.extend(
        [
            item
            for item in user_conf.get("outputs", [])
            if item["type"] not in [i["type"] for i in outputs]
        ]
    )
    if not outputs:
        outputs = default_values.get("outputs", [])
    ret_config["outputs"] = outputs
    ret_config["evaluations"] = merge_lists_by_value(
        default_values["evaluations"],
        user_conf.get("evaluations", []),
        custom_conf.get("evaluations", []),
        unique_key="key",
        merge_fn=_evaluation_merge,
    )
    ret_config["targets"] = merge_lists_by_value(
        user_conf.get("targets", []),
        custom_conf.get("targets", []),
        unique_key="hostname",
    )
    return _validate_config(ret_config)


def get_config(custom_values: Union[dict, None] = None) -> dict:
    user_config = load_config(path.join(CONFIG_PATH, DEFAULT_CONFIG))
    return combine_configs(user_config, custom_values or {})


def base_config() -> dict:
    return yaml.safe_load(
        Path(path.join(str(Path(__file__).parent), "base.yaml")).read_bytes()
    )


def default_config() -> dict:
    conf = base_config()
    conf["evaluations"] = []
    for file_name in glob(
        f"{path.join(str(Path(__file__).parent.parent), 'evaluations')}/**/*.yaml"
    ):
        try:
            conf["evaluations"].append(yaml.safe_load(Path(file_name).read_bytes()))
        except yaml.YAMLError:
            logger.warning(f"bad evaluations file {file_name}")
    conf["MITRE ATT&CK 11.2"] = yaml.safe_load(
        Path(path.join(str(Path(__file__).parent), "mitre_attack.yaml")).read_bytes()
    )
    conf["PCI DSS 3.2.1"] = yaml.safe_load(
        Path(path.join(str(Path(__file__).parent), "pci_dss_3.2.1.yaml")).read_bytes()
    )
    conf["PCI DSS 4.0"] = yaml.safe_load(
        Path(path.join(str(Path(__file__).parent), "pci_dss_4.0.yaml")).read_bytes()
    )
    return conf


def load_config(filename: str = DEFAULT_CONFIG) -> dict:
    config_path = Path(filename)
    if config_path.is_file():
        logger.debug(config_path.absolute())
        return yaml.safe_load(config_path.read_text(encoding="utf8"))
    return {}
