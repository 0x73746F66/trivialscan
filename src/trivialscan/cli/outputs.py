from dataclasses import asdict
from tlstrust import TrustStore
from tlstrust.context import SOURCES, PLATFORMS, BROWSERS, LANGUAGES
from tlstrust.stores import VERSIONS
from rich.table import Table
from rich.style import Style
from rich import box
from trivialscan import util, validator
from trivialscan.scores import Score
from . import config

__module__ = "trivialscan.cli.outputs"


def _make_table(result: validator.Validator, title: str, caption: str) -> Table:
    title_style = Style(
        bold=True,
        color=config.CLI_COLOR_OK if result.certificate_valid else config.CLI_COLOR_NOK,
    )
    table = Table(title=title, caption=caption, title_style=title_style, box=box.SIMPLE)
    table.add_column("", justify="right", style="dark_turquoise", no_wrap=True)
    table.add_column("Result", justify="left", no_wrap=False)
    return table


def _table_data(result: validator.Validator, table: Table, skip: list[str]) -> Table:
    if "verification_details" not in skip:
        for i, err in enumerate(result.certificate_verify_messages):
            if any(key.startswith("pci_") for key in skip) and err.startswith("PCI"):
                continue
            if any(key.startswith("fips_") for key in skip) and err.startswith("FIPS"):
                continue
            if any(key.startswith("nist_") for key in skip) and err.startswith("NIST"):
                continue
            table.add_row(f"Note {i+1}", err)
    for key in result.validation_checks.keys():
        if key in skip:
            continue
        table.add_row(
            config.STYLES.get(key, {}).get("text", key),
            util.styled_boolean(
                result.validation_checks[key],
                config.STYLES[key]["represent_as"],
                config.STYLES[key]["colors"],
            ),
        )
    for key in result.compliance_checks.keys():
        if key in skip:
            continue
        table.add_row(
            config.STYLES.get(key, {}).get("text", key),
            util.styled_boolean(
                result.compliance_checks[key],
                config.STYLES[key]["represent_as"],
                config.STYLES[key]["colors"],
            ),
        )
    for key in list(vars(result.metadata).keys()):
        if key in skip:
            continue
        val = getattr(result.metadata, key)
        if key in config.FINGERPRINTS and isinstance(val, str):
            table.add_row(
                config.STYLES.get(key, {}).get("text", key),
                util.str_n_split(val).upper(),
            )
            continue
        if val is None or (isinstance(val, str) and len(val) == 0):
            table.add_row(
                config.STYLES.get(key, {}).get("text", key),
                util.styled_value(
                    config.STYLES[key].get("null_as", "Unknown"),
                    color=config.STYLES[key].get("null_color", config.CLI_COLOR_NULL),
                ),
            )
            continue
        if isinstance(val, str) and len(val) > 0:
            table.add_row(
                config.STYLES.get(key, {}).get("text", key),
                util.styled_value(val, color=config.STYLES[key].get("color")),
            )
            continue
        if isinstance(val, bool):
            table.add_row(
                config.STYLES.get(key, {}).get("text", key),
                util.styled_boolean(
                    val,
                    represent_as=config.STYLES[key]["represent_as"],
                    colors=config.STYLES[key]["colors"],
                ),
            )
            continue
        table.add_row(config.STYLES.get(key, {}).get("text", key), util.styled_any(val))
    return table


def _table_ext(result: validator.Validator, table: Table, skip: list[str]) -> Table:
    if "extensions" in skip:
        return table
    for v in result.metadata.certificate_extensions:
        ext_data = v.copy()
        ext = ext_data["name"]
        del ext_data["name"]
        if ext in skip:
            continue
        if ext in ext_data:
            ext_sub = ext_data[ext]
            del ext_data[ext]
            table.add_row(f"Extension {ext}", util.styled_dict(ext_data))
            if isinstance(ext_sub, list):
                for sub in ext_sub:
                    if isinstance(sub, str):
                        table.add_row("", util.styled_value(sub))
                        continue
                    if isinstance(sub, dict):
                        for subk, subv in sub.items():
                            if subv is None:
                                table.add_row("", util.styled_value(subk))
                            else:
                                table.add_row("", subk + "=" + util.styled_any(subv))
                        continue
                    table.add_row("", util.styled_any(sub))
                continue
            table.add_row("", str(ext_sub))
            continue
        table.add_row(f"Extension {ext}", util.styled_any(ext_data))
    return table


def table_score(score_card: Score, rating_color: str, target: str) -> Table:
    table = Table(box=box.SIMPLE_HEAD)
    table.add_column(
        f"Security Score Card {target}",
        justify="right",
        style="dark_turquoise",
        no_wrap=True,
    )
    table.add_column("", justify="left", no_wrap=False)
    table.add_row(
        "Rating",
        util.styled_any(config.RATING_ASCII[score_card.rating]),
        style=rating_color,
    )
    table.add_row("Rating cap", util.styled_value(score_card.rating_cap))
    table.add_row(
        "Security score",
        util.styled_value(f"{score_card.result}/{score_card.security_score_best}"),
    )
    for label, values in score_card.scoring_results.items():
        if values:
            table.add_row(label, util.styled_list(values))
    if score_card.rating_cap_reason:
        table.add_row(
            "Rating cap reason", util.styled_list(score_card.rating_cap_reason)
        )
    table.add_row("Trust summary", util.styled_value(score_card.trust_summary))
    if score_card.risk_summary:
        table.add_row("Risk summary", util.styled_list(score_card.risk_summary))
    return table


def peer_outputs(result: validator.PeerCertValidator) -> Table:
    peer_type = "Intermediate Certificate"
    if result.metadata.certificate_intermediate_ca:
        peer_type = "Intermediate CA"
    title = f"{peer_type}: {result.metadata.certificate_subject}"
    caption = "\n".join(
        [
            f"Issuer: {result.metadata.certificate_issuer}",
            util.date_diff(result.certificate.not_valid_after),
        ]
    )
    table = _make_table(result, title, caption)
    table.add_row(
        config.STYLES["certificate_valid"]["text"],
        util.styled_boolean(
            result.certificate_valid,
            config.STYLES["certificate_valid"]["represent_as"],
            config.STYLES["certificate_valid"]["colors"],
        ),
    )
    _table_data(result, table, config.PEER_SKIP)
    _table_ext(result, table, config.PEER_SKIP)
    return table


def root_outputs(result: validator.RootCertValidator) -> Table:
    title = f"Root CA: {result.metadata.certificate_subject}"
    caption = util.date_diff(result.certificate.not_valid_after)
    table = _make_table(result, title, caption)
    table.add_row(
        config.STYLES["certificate_valid"]["text"],
        util.styled_boolean(
            result.certificate_valid,
            ("Trusted", "Not Trusted"),
            config.STYLES["certificate_valid"]["colors"],
        ),
    )
    _table_data(result, table, config.ROOT_SKIP)
    _table_ext(result, table, config.ROOT_SKIP)
    return table


def server_outputs(result: validator.LeafCertValidator) -> Table:
    title = f"Leaf Certificate {result.metadata.host}:{result.metadata.port} ({result.metadata.peer_address})"
    caption = "\n".join(
        [
            f"Issuer: {result.metadata.certificate_issuer}",
            util.date_diff(result.certificate.not_valid_after),
        ]
    )
    table = _make_table(result, title, caption)
    table.add_row(
        config.STYLES["certificate_valid"]["text"],
        util.styled_boolean(
            result.certificate_valid,
            config.STYLES["certificate_valid"]["represent_as"],
            config.STYLES["certificate_valid"]["colors"],
        ),
    )
    table.add_row(
        config.STYLES["certificate_chain_valid"]["text"],
        util.styled_boolean(
            result.certificate_chain_valid,
            config.STYLES["certificate_chain_valid"]["represent_as"],
            config.STYLES["certificate_chain_valid"]["colors"],
        ),
    )
    table.add_row(
        config.STYLES["certificate_chain_validation_result"]["text"],
        util.styled_any(result.certificate_chain_validation_result),
    )
    _table_data(result, table, config.SERVER_SKIP)
    _table_ext(result, table, config.SERVER_SKIP)
    return table


def validator_data(
    result: validator.Validator, certificate_type: str, skip_keys: list
) -> dict:
    data = asdict(result.metadata)
    data["certificate_valid"] = result.certificate_valid
    if isinstance(result, validator.LeafCertValidator):
        data["certificate_chain_valid"] = result.certificate_chain_valid
        data[
            "certificate_chain_validation_result"
        ] = result.certificate_chain_validation_result
    data["certificate_type"] = certificate_type
    data["expiry_status"] = util.date_diff(result.certificate.not_valid_after)
    data["verification_results"] = {}
    data["compliance_results"] = {}
    data["verification_details"] = data.get("verification_details", {})
    for key, value in result.validation_checks.items():
        if key in skip_keys:
            continue
        data["verification_results"][key] = value
    for key, value in result.compliance_checks.items():
        if key in skip_keys:
            continue
        data["compliance_results"][key] = value
    if "verification_details" not in skip_keys:
        data["verification_details"] = result.certificate_verify_messages
    if any(key.startswith("pci_") for key in skip_keys):
        data["verification_details"] = [
            detail
            for detail in data["verification_details"]
            if not detail.startswith("PCI")
        ]
    if any(key.startswith("nist_") for key in skip_keys):
        data["verification_details"] = [
            detail
            for detail in data["verification_details"]
            if not detail.startswith("NIST")
        ]
    if any(key.startswith("fips_") for key in skip_keys):
        data["verification_details"] = [
            detail
            for detail in data["verification_details"]
            if not detail.startswith("FIPS")
        ]
    for key in list(vars(result.metadata).keys()):
        if key in skip_keys and key in data:
            del data[key]
    if "extensions" in skip_keys:
        return data
    for v in result.metadata.certificate_extensions:
        if v.get("name") in skip_keys:
            data["certificate_extensions"][:] = [
                d for d in data["certificate_extensions"] if d.get("name") != v["name"]
            ]

    return data


def prepare_json(results: list[validator.Validator], target: str) -> dict:
    if not results:
        return {}
    score_card = Score(results)
    data = {
        "target": target,
        "security_score": score_card.result,
        "security_score_best": score_card.security_score_best,
        "security_score_worst": score_card.security_score_worst,
        "security_scoring_results": score_card.scoring_results,
        "security_scoring_groups": score_card.scores,
        "security_rating": score_card.rating,
        "security_rating_cap": score_card.rating_cap,
        "security_rating_cap_reason": score_card.rating_cap_reason,
        "security_rating_groups": score_card.rating_groups,
        "trust_summary": score_card.trust_summary,
        "risk_summary": score_card.risk_summary,
        "certificate_trust": [],
        "validations": [],
    }
    for result in results:
        if isinstance(result, validator.RootCertValidator):
            data["validations"].append(
                validator_data(
                    result,
                    "Root CA",
                    [x for x in config.ROOT_SKIP if x not in config.JSON_ONLY],
                )
            )
            contexts = {**SOURCES, **PLATFORMS, **BROWSERS, **LANGUAGES}
            trust_store = TrustStore(
                result.metadata.certificate_subject_key_identifier
                if not result.metadata.certificate_authority_key_identifier
                else result.metadata.certificate_authority_key_identifier
            )
            for name, is_trusted in trust_store.all_results.items():
                data["certificate_trust"].append(
                    {
                        "trust_store": name,
                        "is_trusted": is_trusted,
                        "version": VERSIONS[contexts[name]],
                    }
                )
        if isinstance(result, validator.PeerCertValidator):
            cert_type = "Intermediate Certificate"
            if result.metadata.certificate_intermediate_ca:
                cert_type = "Intermediate CA"
            data["validations"].append(
                validator_data(
                    result,
                    cert_type,
                    [x for x in config.PEER_SKIP if x not in config.JSON_ONLY],
                )
            )
        if isinstance(result, validator.LeafCertValidator):
            data["validations"].append(
                validator_data(
                    result,
                    "Leaf Certificate",
                    [x for x in config.SERVER_SKIP if x not in config.SERVER_JSON_ONLY],
                )
            )
    return data
