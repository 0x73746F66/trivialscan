import logging
from os import path
from pathlib import Path
from copy import deepcopy
from urllib.parse import urlparse
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
    # TODO: more config validations
    return combined_config


def combine_configs(user_conf: dict, custom_conf: dict) -> dict:
    default_values = default_config()
    ret_config = {
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
    }
    outputs = user_conf.get("outputs", [])
    outputs.extend(
        [
            item
            for item in custom_conf.get("outputs", [])
            if item["type"] not in [i["type"] for i in outputs]
        ]
    )
    if not outputs:
        outputs = default_values["outputs"]
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


def get_config(custom_values: dict | None = None) -> dict:
    user_config = load_config(path.join(CONFIG_PATH, DEFAULT_CONFIG))
    return combine_configs(user_config, custom_values or {})


def default_config() -> dict:
    return yaml.safe_load(DEFAULT_VALUES)


def load_config(filename: str = DEFAULT_CONFIG) -> dict:
    config_path = Path(filename)
    if config_path.is_file():
        logger.debug(config_path.absolute())
        return yaml.safe_load(config_path.read_text(encoding="utf8"))
    return {}


DEFAULT_VALUES = b"""
---
defaults:
  use_sni: True
  cafiles:
  tmp_path_prefix: /tmp
  http_path: /

outputs:
  - type: console

evaluations:
  - key: client_renegotiation
    group: tls_negotiation
    label_as: Client initiated TLS renegotiation
    issue: >
      Server accepts client-initiated insecure renegotiation, numerous exploits exists and many have been assigned CVE
    cvss2: AV:N/AC:M/Au:N/C:N/I:N/A:C
    cvss3: AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
    cve:
      - CVE-2009-3555
      - CVE-2011-1473
      - CVE-2011-5094
      - CVE-2021-3449
    references:
      - name: RFC 5746 - Transport Layer Security Renegotiation Indication Extension
        url: https://datatracker.ietf.org/doc/html/rfc5746
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Not Detected
        score: 60
      - value: True
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -60

  - key: secure_renegotiation
    group: tls_negotiation
    label_as: Secure Renegotiation
    issue: Client initiated TLS renegotiation allows attackers to leverage known exploits for lower protocols, prevention is possible when implementing Secure Renegotiation described in RFC-5746 section 3.3 implemented using the renegotiation_info extension or the spurious cipher TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    cvss2: AV:N/AC:M/Au:N/C:N/I:N/A:C
    cvss3: AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
    cve:
      - CVE-2009-3555
      - CVE-2011-1473
      - CVE-2011-5094
      - CVE-2021-3449
    references:
      - name: RFC 5746 - Transport Layer Security Renegotiation Indication Extension
        url: https://datatracker.ietf.org/doc/html/rfc5746
    anotate_results:
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -120
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 100

  - key: compression_support
    group: tls_negotiation
    label_as: TLS Compression (CRIME/BEAST)
    issue: Server supports TLS compression which may allow CRIME/BEAST attack
    cvss2: AV:N/AC:H/Au:N/C:P/I:N/A:N
    cvss3: AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N
    cve:
      - CVE-2012-4929
    references:
      - name: RFC 3749 - Transport Layer Security Protocol Compression Methods
        url: https://datatracker.ietf.org/doc/html/rfc3749
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Not Detected
        score: 40
      - value: True
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -40

  - key: tlsa
    group: dns_configuration
    label_as: TLS/A
    issue: >
      DNS by itself is not secure, without TLS/a or DNSSEC ICANN states any attacker can easily redirect a user to any malicious actor controlled server without the user or authentic server realising it
    references:
      - name: ICANN
        url: https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en
      - name: RFC 6840 - Clarifications and Implementation Notes for DNS Security
        url: https://datatracker.ietf.org/doc/html/rfc6840
      - name: RFC 4033 - DNS Security Introduction and Requirements
        url: https://datatracker.ietf.org/doc/html/rfc4033
    anotate_results:
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -200
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Detected
        score: 120

  - key: dnssec
    group: dns_configuration
    label_as: DNSSEC
    issue: DNS by itself is not secure, without DNSSEC ICANN states any attacker can easily redirect a user to any malicious actor controlled server without the user or authentic server realising it
    references:
      - name: ICANN
        url: https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en
      - name: RFC 6014 - Cryptographic Algorithm Identifier Allocation for DNSSEC
        url: https://datatracker.ietf.org/doc/html/rfc6014
      - name: RFC 6840 - Clarifications and Implementation Notes for DNS Security
        url: https://datatracker.ietf.org/doc/html/rfc6840
      - name: RFC 4956 - DNS Security (DNSSEC) Opt-In
        url: https://datatracker.ietf.org/doc/html/rfc4956
      - name: RFC 4033 - DNS Security Introduction and Requirements
        url: https://datatracker.ietf.org/doc/html/rfc4033
    anotate_results:
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Detected
        score: 120

  - key: deprecated_dnssec_algorithm
    group: dns_configuration
    label_as: Avoid deprecated DNSSEC algorithm
    issue: Whenever a DNS zone is signed with a SHA-1 DNSKEY algorithm it is vulnerable to chosen prefix collision attacks. This is a problem when a zone accepts updates from multiple parties, such as; TLDs, enterprises, hosting providers. It is also a problem when a key is re-used by multiple zones
    cvss2: AV:N/AC:L/Au:N/C:P/I:N/A:N
    cvss3: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cve:
      - CVE-2019-14855
    references:
      - name: Cambridge University Information Services
        url: https://www.dns.cam.ac.uk/news/2020-01-09-sha-mbles.html
      - name: Disclosure Paper
        url: https://sha-mbles.github.io/
    anotate_results:
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -100
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80

  - key: private_key_known_compromised
    group: certificate
    label_as: Known Compromised Private Key
    issue: DSA keys, and RSA keys smaller than 1024 bits offer no security and should not be used at all, whether they are known to be compromised or not. The pwnedkeys database keeps records of compromised 1024 bit and larger RSA/DSA keys, as well as elliptic-curve keys on the P-256, P-384, and P-521 curves. If your private key is ever compromised, it should be considered an emergency, and your priority should be resolving the issue immediately. If an unauthorized person gains access to your private key, they can assume the identity that your certificate is intended to protect (e.g. you, your company, and/or your website)
    cvss2: AV:L/AC:H/Au:N/C:P/I:N/A:N
    cvss3: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
    cve:
      - CVE-2007-3108
      - CVE-2008-0166
    references:
      - name: Security Advisory
        url: https://www.debian.org/security/2008/dsa-1571
      - name: OSINT
        url: https://pwnedkeys.com/faq.html
    anotate_results:
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Compromised
        score: -500
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Not Known Compromised
        score: 100
      - value: None
        evaluation_value: "[cyan]SKIP![/cyan]"
        display_as: Not an valid pwnedkeys.com response
        score: 0

  - key: deprecated_protocol_negotiated
    group: tls_negotiation
    label_as: Deprecated TLS protocol negotiated
    issue: >
      When information is sent between the client and the server, it must be encrypted and protected in order to prevent an attacker from being able to read or modify it
      This is most commonly done using HTTPS, which uses the Transport Layer Security (TLS) protocol, a replacement for the deprecated Secure Socket Layer (SSL) protocol
      By default, most servers still support outdated and known vulnerable protocols, typically for backwards compatibility with equally outdated web browser software
      This is known as an insecure default and could lead to trivial attacks against default or misconfigured servers
    cvss2: AV:N/AC:H/Au:N/C:C/I:C/A:N
    cvss3: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
    cve:
      - CVE-2014-8730
      - CVE-2014-0160
      - CVE-2009-3555
    references:
      - name: Testing for Weak SSL TLS Ciphers Insufficient Transport Layer Protection (WSTG-CRYP-01)
        url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 120
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: known_weak_cipher_negotiated
    group: tls_negotiation
    label_as: Known weak ciphers negotiated {negotiated_cipher} ({negotiated_cipher_bits} bits)
    issue: >
      A cipher suite is a combination of authentication, encryption, and message authentication code (MAC) algorithms
      They are used during the negotiation of security settings for a TLS/SSL connection as well as for the transfer of data
      By default, most servers still support outdated and known vulnerable ciphers
      This is known as an insecure default and could lead to trivial attacks against default or misconfigured servers
    cvss2: AV:N/AC:H/Au:N/C:C/I:C/A:N
    cvss3: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
    cve:
      - CVE-2014-6321
      - CVE-2008-0166
    references:
      - name: Testing for Weak SSL TLS Ciphers Insufficient Transport Layer Protection (WSTG-CRYP-01)
        url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 120
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200
    substitutions:
      - negotiated_cipher
      - negotiated_cipher_bits

  - key: known_weak_cipher_offered
    group: tls_negotiation
    label_as: Known weak ciphers offered
    issue: >
      A cipher suite is a combination of authentication, encryption, and message authentication code (MAC) algorithms
      They are used during the negotiation of security settings for a TLS/SSL connection as well as for the transfer of data
      By default, most servers still support outdated and known vulnerable ciphers
      This could lead to trivial attacks against default or misconfigured servers
    cvss2: AV:N/AC:H/Au:N/C:C/I:C/A:N
    cvss3: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
    cve:
      - CVE-2014-6321
      - CVE-2008-0166
    references:
      - name: Testing for Weak SSL TLS Ciphers Insufficient Transport Layer Protection (WSTG-CRYP-01)
        url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 60
      - value: True
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -100

  - key: rc4_cipher_offered
    group: tls_negotiation
    label_as: Known exploited and deprecated RC4 ciphers offered
    issue: TBA
    references:
      - name:
        url:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 60
      - value: True
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -100

  - key: cbc_cipher_offered
    group: tls_negotiation
    label_as: Known exploited and deprecated CBC ciphers offered
    issue: TBA
    references:
      - name:
        url:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 60
      - value: True
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -100

  - key: strong_cipher_negotiated
    group: tls_negotiation
    label_as: Strong ciphers negotiated
    issue: TBA
    references:
      - name:
        url:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 120
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -200

  - key: strong_cipher_offered
    group: tls_negotiation
    label_as: Strong ciphers offered
    issue: TBA
    references:
      - name:
        url:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 60
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -500

  - key: only_strong_ciphers_offered
    group: tls_negotiation
    label_as: Only strong ciphers offered
    issue: TBA
    references:
      - name:
        url:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 400
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -200

  - key: known_weak_signature_algorithm
    group: certificate
    label_as: Deprecated or known weak signature algorithm
    issue: Using our SHA-1 chosen-prefix collision the X.509 Certificate can be forged, other attacks leverage predictable serial numbers and compromise Certificate Authorities issued Certificates
    cvss2: AV:N/AC:L/Au:N/C:P/I:N/A:N
    cvss3: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cve:
      - CVE-2005-4900
      - CVE-2019-14855
    references:
      - name: Disclosure Paper
        url: https://shattered.io/
      - name: CA/Browser Forum
        url: https://cabforum.org/2014/10/16/ballot-118-sha-1-sunset/
      - name: Cambridge University Information Services
        url: https://www.dns.cam.ac.uk/news/2020-01-09-sha-mbles.html
      - name: Disclosure Paper
        url: https://sha-mbles.github.io/
    anotate_results:
      - value: True
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -100
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80

  - key: fallback_scsv
    group: tls_negotiation
    label_as: Downgrade attack prevention (SCSV)
    issue: The TLS Signaling Cipher Suite Value (SCSV) protects against TLS/SSL downgrade attacks. If enabled, the server makes sure that the strongest protocol that both client and server understand is used. Attackers can make a client attempt weaker TLS connections and exploit all the vulnerabilities associated with a given protocol
    cvss2: AV:N/AC:M/Au:N/C:P/I:N/A:N
    cvss3: AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N
    cve:
      - CVE-2014-3566
      - CVE-2014-8730
    references:
      - name: RFC 7507 - TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks
        url: https://datatracker.ietf.org/doc/html/rfc7507
    anotate_results:
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -180
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 120

  - key: tls_robot
    group: tls_negotiation
    label_as: ROBOT Vulnerability
    issue: Timing attack causing padding errors using RSA with PKCS#1 v1.5 session keys allowing any attacker to passively record traffic and later decrypt it
    cvss2: AV:N/AC:H/Au:N/C:C/I:N/A:N
    cvss3: AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:W/RC:C
    cve:
      - CVE-2012-5081
      - CVE-2016-6883
      - CVE-2017-6168
      - CVE-2017-17382
      - CVE-2017-17427
      - CVE-2017-17428
      - CVE-2017-12373
      - CVE-2017-13098
      - CVE-2017-1000385
      - CVE-2017-13099
      - CVE-2017-17841
      - CVE-2018-1388
      - CVE-2018-5762
      - CVE-2017-18268
      - CVE-2017-15533
      - CVE-2018-9192
      - CVE-2018-9194
    references:
      - name: CERT/CC
        url: https://www.kb.cert.org/vuls/id/144389
      - name: Proof of Concept
        url: https://github.com/robotattackorg/robot-detect
      - name: Disclosure Paper
        url: https://www.robotattack.org/
      - name: Disclosure Paper
        url: http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
      - name: Disclosure Paper
        url: https://eprint.iacr.org/2003/052
      - name: Disclosure Paper
        url: https://www.nds.rub.de/media/nds/veroeffentlichungen/2015/08/21/Tls13QuicAttacks.pdf
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 120
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -180
      - value: None
        evaluation_value: "[cyan]EMPTY[/cyan]"
        display_as: Incomplete evaluation (check log with -vvv)
        score: 0

  - key: revocation_crlite
    group: certificate
    label_as: Intermediate Certificate Revocation (crlite)
    issue: Certificate Revocation only occurs if the Certificate is no longer intended to be used for it's designed purpose, and offers no security at best, or represents a known compormise
    cvss2: AV:L/AC:H/Au:N/C:P/I:N/A:N
    cvss3: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
    cve:
    references:
      - name: Security Advisory
        url: https://blog.mozilla.org/security/tag/crlite/
    anotate_results:
      - value: Revoked
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Revoked
        score: -200
      - value: Expired
        evaluation_value: "[khaki1]WARN! Expired[/khaki1]"
        display_as: Expired
        score: 0
      - value: Good
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Not Revoked
        score: 80
      - value: NotCovered
        evaluation_value: "[khaki1]WARN! NotCovered[/khaki1]"
        display_as: NotCovered
        score: -100
      - value: NotEnrolled
        evaluation_value: "[khaki1]WARN! NotEnrolled[/khaki1]"
        display_as: NotEnrolled
        score: -100

  - key: possible_phish_or_malicious
    group: certificate
    label_as: Malicious Certificate
    issue: >
      Malicious certificates are most commonly signed by trusted certificate authority roots, to evade detection
      by blending in with legitimate traffic and making use of encryption to help hide their payloads.
      Both commodity and targeted attack malware make heavy use of encrypted command-and-control (C&C) that is
      indistinguishable from regular traffic, and ethical actors (with permission granted) will leverage tools
      called intrusion frameworks like; Cobalt Strike, Metasploit, and Core Impact that should be identified
      as though these were unauthorised because bad actors will attempt to emulate a penetration tester in
      order to take advantage of a trust relationship and infect you regardless.
      Phishing websites will use these malicious certificates that are identical to legitimate certificates which
      gives a false sense of security to victims who observe the strong encryption being used in their browser
    compliance:
      "PCI DSS":
        - version: 3.2.1
          requirements:
            - 5.2
            - 6.5.4
            - 6.6
        - version: 4.0
          requirements:
            - 3.7.5
            - 5.2.2
            - 6.4.1
            - 6.4.2
            - A2.1
    references:
      - name: Analyzing SSL/TLS Certificates Used by Malware (Trend Micro)
        url: https://webcache.googleusercontent.com/search?q=cache:lXyCnKFb3acJ:https://www.trendmicro.com/en_us/research/21/i/analyzing-ssl-tls-certificates-used-by-malware.html+&cd=1&hl=en&ct=clnk&gl=au
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Not Known Compromised
        score: 40
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral] {reason}"
        display_as: Compromised
        score: -200
    substitutions:
      - sha1_fingerprint

  - key: known_weak_keys
    group: certificate
    label_as: Known Weak key usage {public_key_type}-{public_key_size}
    issue: >
      Continued use of weak keys in certificates puts your sensitive data at risk. Exhaustive key searches or brute force attacks against certificates with weak keys are dangerous to network security.
      As computational power increases, so does the need for stronger keys.
      Diffie-Hellman key exchange depends for its security on the presumed difficulty of solving the discrete logarithm problem.
      By design, many Diffie-Hellman implementations use the same pre-generated prime for their field, because of the reuse of primes generating precomputation for just one prime would expose millions of implementations. This vulnerability was known as early as 1992.
      Claims on the practical implications of the attack at the time were however disputed by security researchers but over the years it is expected that many primes were and still are being calculated practically making all primes of 2048 bit or less considered weak or vulnerable.
    references:
      - name: RFC 8270 - Increase the Secure Shell Minimum Recommended Diffie-Hellman Modulus Size to 2048 Bits
        url: https://datatracker.ietf.org/doc/html/rfc8270
      - name: Eyal Ronen and Adi Shamir - Critical Review of Imperfect Forward Secrecy
        url: http://www.wisdom.weizmann.ac.il/~eyalro/RonenShamirDhReview.pdf
      - name: Logjam Attack - Imperfect Forward Secrecy, How Diffie-Hellman Fails in Practice
        url: https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf
      - name: TLS/SSL certificate weak key vulnerability - DigiCert
        url: https://docs.digicert.com/certificate-tools/discovery-user-guide/tlsssl-certificate-vulnerabilities/weak-keys/
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 200
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Vulnerable
        score: -500
    substitutions:
      - public_key_type
      - public_key_size

  - key: weak_rsa_public_exponent
    group: certificate
    label_as: Known Weak RSA public key exponent {public_key_exponent}
    issue: >
      Using anything other than 65537 as the public exponent would effect compatibility with most hardware and software.
      Lower isn't vulnerable with proper padding however RSA implementations are widely flawed and did not consider this security characteristic therefore in practice any low exponent could indicate weakness known to be exploited by many heavily scrutinised researchers publications.
      Using exatly 65537 is an industry standard prescribed by certification authorities and compliance such as PCI DSS, Annex B.3 of FIP186-4, NIST Special Publication on Computer Security (SP 800-78 Rev. 1 of August 2007) does not allow public exponents e smaller than 65537.
    references:
      - name: Twenty Years of Attacks on the RSA Cryptosystem - Dan Boneh, Stanford University
        url: https://www.researchgate.net/publication/2538368_Twenty_Years_of_Attacks_on_the_RSA_Cryptosystem
    compliance:
      "PCI DSS":
        - version: 3.2.1
          requirements:
            - 3.5
            - 6.5.3
        - version: 4.0
          requirements:
            - 2.2.7
            - 3.3.2
            - 3.3.3
            - 3.5.1
            - 3.6.1
            - 4.2.1
            - 4.2.2
            - 6.2.4
            - 8.3.2
            - A2
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 60
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Vulnerable
        score: -200
    substitutions:
      - public_key_exponent

  - key: rsa_public_key_issue
    group: certificate
    label_as: RSA public key exponent {public_key_exponent} has known issues
    issue: >
      Using anything other than 65537 as the public exponent would effect compatibility with most hardware and software.
      Any higher exponent would make the public RSA operation, used for encryption or signature verification, unusably slower.
      Using a larger exponent will not decrease security, but will be more time / power consuming.
    references:
      - name: Twenty Years of Attacks on the RSA Cryptosystem - Dan Boneh, Stanford University
        url: https://www.researchgate.net/publication/2538368_Twenty_Years_of_Attacks_on_the_RSA_Cryptosystem
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 20
      - value: True
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Problematic
        score: -500
    substitutions:
      - public_key_exponent

  - key: valid_common_name
    group: certificate
    label_as: Valid Certificate Common Name
    issue: >
      This is frequently a misconfiguration, i.e. the website domain name was not included in your common name by mistake.
      However it is a very uncommon issue and is most likely indication of compromise, where a malicious attacker is targeting website owners or visitors using phishing or impersonation and have made the error unintentionally or was unable to effectively impersonate the website correctly and are relying on visitors ignoring browser warnings.
    references:
      - name: RFC 9110 - HTTP Semantics
        url: https://datatracker.ietf.org/doc/html/rfc9110
      - name: DNSimple - What is the Certificate Common Name
        url: https://support.dnsimple.com/articles/what-is-common-name/
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 20
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -100

  - key: valid_host_name
    group: certificate
    label_as: Hostname matches Certificate
    issue: >
      This is frequently a misconfiguration, i.e. the website domain name was not included in your common name by mistake.
      However it is a very uncommon issue and is most likely indication of compromise, where a malicious attacker is targeting website owners or visitors using phishing or impersonation and have made the error unintentionally or was unable to effectively impersonate the website correctly and are relying on visitors ignoring browser warnings.
    references:
      - name: RFC 9110 - HTTP Semantics
        url: https://datatracker.ietf.org/doc/html/rfc9110
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 50
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Misconfigured
        score: -150

  - key: certification_version
    group: certificate
    label_as: X.509 Certificates are in version 3
    issue: >
      HIPAA, Security Rule (Ref. NIST SP 800-52: Guidelines for the Selection and Use of TLS Implementations)
      Require all the X509 certificates provided by the server are in version 3.
    references:
      - name: NIST SP 800-52 - Guidelines for the Selection and Use of TLS Implementations
        url: https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html
      - name: HIPAA / HITECH
        url: https://www.hhs.gov/hipaa/index.html
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Compliant
        score: 20
      - value: False
        evaluation_value: "[khaki1]WARN![/khaki1]"
        display_as: Non-compliant
        score: -50

  - key: certification_expired
    group: certificate
    label_as: Certificate is not expired
    issue: >
      When visiting a website that uses an expired Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 50

  - key: valid_issued_date
    group: certificate
    label_as: Valid NotBefore date
    issue: >
      When visiting a website that uses a Certificate with an invalid NotBefore date, it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 20
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -100

  - key: is_self_signed
    group: certificate
    label_as: Certificate self-signed
    issue: >
      Any self-signed Certificate should be untrusted as it offers no security characteristics of TLS that is based on a system that all Certificates have a Root Certificate Authory Trust Anchor.
      When visiting a website that uses a self-signed Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Compromised
        score: -200
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 50

  - key: trust_javase
    group: certificate
    label_as: Trust Store - Java SE
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_ccadb
    group: certificate
    label_as: Trust Store - CCADB
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_rust
    group: certificate
    label_as: Trust Store - Rust
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_froyo
    group: certificate
    label_as: Trust Store - Android 2.2 Froyo
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_gingerbread
    group: certificate
    label_as: Trust Store - Android 2.3 Gingerbread
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_honeycomb
    group: certificate
    label_as: Trust Store - Android 3 Honeycomb
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_ice_cream_sandwich
    group: certificate
    label_as: Trust Store - Android 4 Ice Cream Sandwich
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_kitkat
    group: certificate
    label_as: Trust Store - Android 4.4 KitKat
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_nougat
    group: certificate
    label_as: Trust Store - Android 7 Nougat
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_oreo
    group: certificate
    label_as: Trust Store - Android 8 Oreo
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_pie
    group: certificate
    label_as: Trust Store - Android 9 Pie
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_quince_tart
    group: certificate
    label_as: Trust Store - Android 10 Quince Tart
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_red_velvet_cake
    group: certificate
    label_as: Trust Store - Android 11 Red Velvet Cake
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_snow_cone
    group: certificate
    label_as: Trust Store - Android 12 Snow Cone
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_tiramisu
    group: certificate
    label_as: Trust Store - Android 13 Tiramisu
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_android_upside_down_cake
    group: certificate
    label_as: Trust Store - Android 14 Upside Down Cake
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_certifi
    group: certificate
    label_as: Trust Store - certifi (Python module)
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_russian
    group: certificate
    label_as: Trust Store - MinTsifry Rossii (Russian)
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_libcurl
    group: certificate
    label_as: Trust Store - libcurl
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: trust_dart
    group: certificate
    label_as: Trust Store - Dart Native
    issue: >
      Certificates should be treated as suspicious when they do not have a trusted Root Certificate Authory, as it offers no security characteristics of TLS built on Trust Anchor system.
      When visiting a website that uses an untrusted Certificate it is likely the TLS connection is not secure.
    references:
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Trusted
        score: 100
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Not Trusted
        score: -500

  - key: basic_constraints_path_length
    group: tls_negotiation
    label_as: Basic Constraints Extension valid path length
    issue: >
      Path length gives the maximum number of intermediate certificates that may follow the root CA certificate typically (or certificate otherwise specifying the constraint) in a valid certification path.
    references:
      - name: RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
        url: https://datatracker.ietf.org/doc/html/rfc5280
    anotate_results:
      - value: True
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 50
      - value: False
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -120

  - key: issuer_validation_type
    group: certificate
    label_as: issuer_validation_type
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: leaf_ca
    group: certificate
    label_as: Leaf Certificate allows impersonation
    issue: >
      Server (leaf) certificates should not be a CA, it could enable impersonation attacks
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: revocation_ocsp_deprecated_algo
    group: certificate
    label_as: revocation_ocsp_deprecated_algo
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: revocation_ocsp_deprecated_sig
    group: certificate
    label_as: revocation_ocsp_deprecated_sig
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: revocation_ocsp_must_staple
    group: certificate
    label_as: revocation_ocsp_must_staple
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: revocation_ocsp_staple
    group: certificate
    label_as: revocation_ocsp_staple
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: revocation_ocsp
    group: certificate
    label_as: revocation_ocsp
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: valid_key_extended_usage
    group: certificate
    label_as: valid_key_extended_usage
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: valid_key_usage
    group: certificate
    label_as: valid_key_usage
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: client_auth_expected
    group: certificate
    label_as: client_auth_expected
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: client_auth_permitted
    group: certificate
    label_as: client_auth_permitted
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: client_auth_valid_subject
    group: certificate
    label_as: client_auth_valid_subject
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: client_authentication
    group: certificate
    label_as: client_authentication
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: compression_support
    group: transport
    label_as: compression_support
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: fips
    group: compliance
    label_as: FIPS
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: nist
    group: compliance
    label_as: NIST
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: pci_dss_3_2
    group: compliance
    label_as: PCI DSS 3.2.1
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: pci_dss_4_0
    group: compliance
    label_as: PCI DSS 4.0
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_coep
    group: transport
    label_as: header_coep
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_coop
    group: transport
    label_as: header_coop
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_corp
    group: transport
    label_as: header_corp
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_csp
    group: transport
    label_as: header_csp
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_expectct
    group: transport
    label_as: header_expectct
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_hsts
    group: transport
    label_as: header_hsts
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_nosniff
    group: transport
    label_as: header_nosniff
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_referrer_policy
    group: transport
    label_as: header_referrer_policy
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_xfo
    group: transport
    label_as: header_xfo
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: header_xss
    group: transport
    label_as: header_xss
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: proto_version_h2c
    group: transport
    label_as: proto_version_h2c
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: proto_version_http1_1
    group: transport
    label_as: proto_version_http1_1
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: proto_version_http1
    group: transport
    label_as: proto_version_http1
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: proto_version_http2
    group: transport
    label_as: proto_version_http2
    issue: >
      TODO
    references:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 80
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

"PCI DSS 3.2.1":
  1: Configure and use firewalls to protect cardholder data
  1.1: Create and implement standards for configuration of firewalls and routers
  1.2: Create a firewall and router configuration that restricts connections between untrusted networks and all system components in the cardholder data environment
  1.3: Restrict direct global access to any system component of the cardholder data medium over the internet
  1.4: Install personal firewall software on all mobile devices that are connected to the internet and used to access the network when they are out of the network
  1.5: Make sure that security policies and operational procedures for managing firewalls are documented, in use, and known to all affected parties
  2: Do not use the vendor's default settings for system passwords and other security parameters
  2.1: Always change the default settings and values provided by the manufacturer and remove or disable unnecessary default accounts before installing any system on the network
  2.2: Create configuration standards for all components of the system
  2.3: Encrypt all non-console administrative access to devices using strong encryption
  2.4: Keep an inventory of all PCI DSS in-scope system components
  2.5: Make sure that security policies and operational procedures are documented, in use, and known to all affected parties to manage the manufacturer's default values and other safety parameters
  2.6: Shared hosting service providers must protect the environment and cardholder data hosted by each organization
  3: Protect stored cardholder data
  3.1: Keep cardholder data storage to a minimum by developing and implementing policies, procedures and processes for data retention and destruction of cardholder data (CHD)
  3.2: Do not store sensitive authentication data after authorization, even if it is encrypted
  3.3: If the primary account number (PAN) has to be displayed, mask it to view it
  3.4: Make the primary account number unreadable wherever it is stored
  3.5: Create and implement procedures to protect the keys used to protect stored cardholder data from disclosure and misuse
  3.6: Document and implement all key management processes and encryption key procedures used to encrypt cardholder data
  3.7: Security policies and operational procedures must be documented, used and known to all affected parties to protect stored cardholder data
  4: Encrypt cardholder data when transmitting over open, public networks
  4.1: Use strong encryption and security protocols to protect sensitive cardholder data during transmission over open, public networks
  4.2: Never send Primary Account Number (PAN) information without password over end-user messaging technologies
  4.3: To encrypt the transmission of cardholder data, ensure that security policies and operational procedures are documented, in use, and known to all affected parties
  5: Protect all systems against malware and update anti-virus software regularly
  5.1: Install anti-virus software on all systems that are commonly affected by malware
  5.2: Make sure all anti-virus mechanisms are working properly
  5.3: Anti-virus software should work effectively and cannot be disabled by users
  5.4: Ensure that security policies and operational procedures are documented, in use, and known to all affected parties to protect systems against malware
  6: Develop and maintain secure systems and applications
  6.1: Establish a process to identify vulnerabilities using reputable outside sources and assign a risk ranking to newly discovered vulnerabilities
  6.2: Ensure that all system components and software are protected from known vulnerabilities by installing the applicable security patches provided by the manufacturer. Install critical security patches within a month
  6.3: Develop internal and external software applications securely
  6.3.1: Remove development, test or custom application accounts, user IDs, and passwords before applications become active or available to customers
  6.3.2: Perform code reviews before applications are become active or released to customers to identify possible coding vulnerabilities
  6.4: Follow change control processes and procedures for all changes to system components
  6.4.1: Separate development and test environments from live environments and implement separation with access controls
  6.4.2: Separation of duties between development, testing and live environments is required
  6.4.3: Production data (live PANs) are not used for testing or development
  6.4.4: Test data and accounts must be removed from system components before the system is enabled before going live
  6.4.5: Change control procedures should include the following
  6.4.5.1: Document the impact of the change
  6.4.5.2: Changes require documented change approval by authorized parties
  6.4.5.3: Perform functionality test to verify that the change does not adversely affect the security of the system
  6.4.5.4: Establish back-out procedures for changes
  6.4.6: After a significant change is complete, all relevant PCI DSS requirements should be applied to all new or modified systems and networks, and documentation updated accordingly
  6.5: Address common coding vulnerabilities in software development processes
  6.5.1: Consider injection flaws, specifically SQL injection, also OS Command Injection, LDAP and XPath injection flaws as well as other injection flaws
  6.5.2: >
    Buffer overflows; attackers can be used to do all kinds of operations if appropriate border controls are not applied. When this happens, the attacker will have the ability to add malicious code to the end of the buffer and then push the malicious code into executable memory space by overflowing the buffer. The malicious code is then run and usually allows the attacker remote access to the application or the infected system.
    To avoid buffer overflows, encoding techniques including:
    - Appropriate boundary controls should be implemented.
    - Input data must be truncated accordingly.
  6.5.3: >
    Insecure cryptographic storage should be handled with the following coding techniques:
    - Cryptographic flaws must be prevented.
    - Strong cryptographic algorithms and keys should be used.
  6.5.4: Unsecured communications need to be handled with coding techniques that properly encrypt all sensitive communications.
  6.5.5: Improper error handling should be determined in software development policies, and procedures and error messages should be handled with information-proof coding techniques.
  6.5.6: All high risk vulnerabilities identified during the vulnerability identification process must be addressed
  6.5.7: Cross-Site Scripting (XSS)
  6.5.8: >
    Inappropriate access control
    A direct object reference occurs when a developer presents a reference to an internal application object, such as a file, directory, database record, or key, as a URL or form parameter. Attackers can change these references to access other unauthorized objects.
    Access controls must be applied consistently at the application layer and business logic for all URLs. The only way for an application to protect sensitive functionality is to prevent links or URLs from being viewed by unauthorized users.
    Attackers can perform unauthorized actions by directly accessing these URLs. An attacker can enumerate and navigate the directory structure of a website so that they can gain access to unauthorized information and learn more about the functioning of the site for later exploitation.
    If user interfaces allow access to unauthorized functions, this access can result in unauthorized persons gaining access to privileged credentials or cardholder data. Only authorized users should be allowed to access direct object references to sensitive resources. Limiting access to data sources will help prevent cardholder data from being made available to unauthorized sources.
    Unsafe direct object references in software development policies and procedures, inability to restrict URL access or inappropriate access control, such as directory traversal, should be addressed with coding techniques that include:
    - Users must be properly authenticated.
    - Entries should be sanitized.
    - Internal object references should not be disclosed to users.
    - User interfaces that do not allow access to unauthorized functions should be designed.
  6.5.9: Cross-site request forgery (CSRF)
  6.5.10: Broken authentication and session management
  6.6: Constantly address new threats and vulnerabilities for Internet-facing web applications and ensure that these applications are protected from known attacks
  6.7: Ensure security policies and operational procedures for developing and maintaining secure systems and applications are documented, in use, and known to all affected parties
  7: Restrict access to cardholder data based on business requirements
  7.1: Limit access to system components and cardholder data only to those who need it for their job functions
  7.2: Create secure access control systems
  7.3: Ensure that security policies and operational procedures to restrict access to cardholder data are documented, in use, and known to all affected parties
  8: Identify and authenticate access to system components
  8.1: Define and implement policies and procedures to ensure correct user identity management for users and administrators across all system components
  8.2: Provide appropriate user authentication management for users and administrators in all system components
  8.3: Secure all individual administrative access to the CDE and all remote access to the CDE using multi-factor authentication
  8.4: Document and communicate authentication policies and procedures to all users
  8.5: Do not use group, shared or public IDs, passwords or other authentication methods
  8.6: Where other authentication mechanisms are used, the use of these mechanisms should be assigned as follows
  8.7: Limit all access to any database containing cardholder data
  8.8: Ensure that security policies and operational procedures for authentication and identification are documented, in use, and known to all affected parties
  9: Restrict physical access to cardholder data
  9.1: Create and use appropriate facility access controls to limit and monitor physical access to systems in the cardholder data environment
  9.2: Develop procedures to distinguish between staff and visitors easily
  9.3: Restrict physical access to sensitive areas for employees as follows
  9.4: Follow procedures to identify and empower visitors
  9.5: Protect all media that contains physically sensitive data
  9.6: Have strict control over the internal or external distribution and transmission of any media
  9.7: Have strict control over media storage and accessibility
  9.8: Destroy media when it is no longer needed for business or legal reasons
  9.9: Protect devices that receive payment card data through physical interaction from tampering and replacement
  9.10: Ensure that security policies and operational procedures to restrict physical access to cardholder data are documented, in use, and known to all affected parties
  10: Track and monitor all access to network resources and cardholder data
  10.1: Create a process that connects access to system components to each user
  10.2: Set up an automatic log review mechanism to reproduce events
  10.3: Record at least the following information for events occurring in all system components
  10.4: Synchronize all critical system clocks and times using time synchronization technology
  10.5: Keep the logs in a way that cannot be altered
  10.6: Regularly review logs and security events for all system components to identify abnormalities or suspicious activity
  10.7: Retain the log history for at least one year and have at least three months of data ready for analysis
  10.8: Create and implement processes for timely detection and reporting of failures of critical security control systems for service providers
  10.9: Ensure that security policies and operational procedures are documented, in use, and known to all affected parties to monitor all access to network resources and cardholder data
  11: Test security systems and processes regularly
  11.1: Create processes to test the presence of wireless access points (802.11), and identify all authorized and unauthorized wireless access points quarterly
  11.2: Perform internal and external network vulnerability scans at least every three months and after a significant change in the network
  11.3: Apply a methodology for penetration testing
  11.4: Use intrusion detection or intrusion prevention techniques to detect or prevent network intrusion
  11.5: Set up a change detection mechanism to detect unauthorized modification of critical system files, configuration files or content files
  11.6: Ensure that security policies and operational procedures for security monitoring and testing are documented, in use, and known to all affected parties
  12: Create a policy that addresses information security for all staff
  12.1: Create and publish an information security policy
  12.2: Create and implement a risk assessment process
  12.3: Acceptable usage policies for critical technologies should be developed, and the appropriate use of these technologies should be defined
  12.4: Ensure that security policy and procedures clearly define information security responsibilities for all personnel
  12.5: Assign information security management responsibilities to a person or team
  12.6: Implement a formal information security awareness program to inform all staff about the importance of cardholder data security
  12.7: To minimize the risk of attack from local sources, run a history scan of candidates before hiring
  12.8: Create and implement policies and procedures to manage service providers where cardholder data is shared, or that may affect the security of cardholder data
  12.9: Service providers must notify their customers in writing that they are responsible for the security of the cardholder data they store, process or transmit on behalf of the customer
  12.10: Create and implement an incident response plan. Be prepared to respond immediately to violations
  12.11: Service providers should evaluate at least quarterly to verify that personnel are following security policies and operational procedures

"PCI DSS 4.0":
  1: Install and Maintain Network Security Controls
  1.1: Processes and mechanisms for installing and maintaining network security controls are defined and understood
  1.1.1: All security policies and operational procedures that are identified in Requirement 1 are; Documented, Kept up to date, In use, Known to all affected parties
  1.1.2: Roles and responsibilities for performing activities in Requirement 1 are documented, assigned, and understood
  1.2: Network security controls (NSCs) are configured and maintained
  1.2.1: Configuration standards for NSC rulesets are; Defined, Implemented, Maintained
  1.2.2: All changes to network connections and to configurations of NSCs are approved and managed in accordance with the change control process defined at Requirement 6.5.1.
  1.2.3: An accurate network diagram(s) is maintained that shows all connections between the CDE and other networks, including any wireless networks
  1.2.4: A3.7.5n accurate data-flow diagram(s) is maintained that meets the following; Shows all account data flows across systems and networks, Updated as needed upon changes to the environment
  1.2.5: All services, protocols, and ports allowed are identified, approved, and have a defined business need
  1.2.6: Security features are defined and implemented for all services, protocols, and ports that are in use and considered to be insecure, such that the risk is mitigated
  1.2.7: Configurations of NSCs are reviewed at least once every six months to confirm they are relevant and effective
  1.2.8: >
    Configuration files for NSCs are:
    - Secured from unauthorized access
    - Kept consistent with active network configurations
  1.3: Network access to and from the cardholder data environment is restricted
  1.3.1: >
    Inbound traffic to the CDE is restricted as follows:
    - To only traffic that is necessary.
    - All other traffic is specifically denied.
  1.3.2: >
    Outbound traffic from the CDE is restricted as follows:
    - To only traffic that is necessary.
    - All other traffic is specifically denied.
  1.3.3: >
    NSCs are installed between all wireless networks and the CDE, regardless of whether the wireless network is a CDE, such that:
    - All wireless traffic from wireless networks into the CDE is denied by default.
    - Only wireless traffic with an authorized business purpose is allowed into the CDE.
  1.4: Network connections between trusted and untrusted networks are controlled
  1.4.1: NSCs are implemented between trusted and untrusted networks
  1.4.2: >
    Inbound traffic from untrusted networks to trusted networks is restricted to:
    - Communications with system components that are authorized to provide publicly accessible services, protocols, and ports.
    - Stateful responses to communications initiated by system components in a trusted network.
    - All other traffic is denied.
  1.4.3: Anti-spoofing measures are implemented to detect and block forged source IP addresses from entering the trusted network.
  1.4.4: System components that store cardholder data are not directly accessible from untrusted networks.
  1.4.5: The disclosure of internal IP addresses and routing information is limited to only authorized parties.
  1.5: Risks to the CDE from computing devices that are able to connect to both untrusted networks and the CDE are mitigated.
  1.5.1: >
    Security controls are implemented on any computing devices, including company- and employee-owned devices, that connect to both untrusted networks (including the Internet) and the CDE as follows:
    - Specific configuration settings are defined to prevent threats being introduced into the entity's network.
    - Security controls are actively running.
    - Security controls are not alterable by users of the computing devices unless specifically documented and authorized by management on a case-by-case basis for a limited period.
  2: Apply Secure Configurations to All System Components
  2.1: Processes and mechanisms for applying secure configurations to all system components are defined and understood.
  2.1.1: >
    All security policies and operational procedures that are identified in Requirement 2 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  2.1.2: Roles and responsibilities for performing activities in Requirement 2 are documented, assigned, and understood.
  2.2: System components are configured and managed securely
  2.2.1: >
    Configuration standards are developed, implemented, and maintained to:
    - Cover all system components.
    - Address all known security vulnerabilities.
    - Be consistent with industry-accepted system hardening standards or vendor hardening recommendations.
    - Be updated as new vulnerability issues are identified, as defined in Requirement 6.3.1.
    - Be applied when new systems are configured and verified as in place before or immediately after a system component is connected to a production environment.
  2.2.2: >
    Vendor default accounts are managed as follows:
    - If the vendor default account(s) will be used, the default password is changed per Requirement 8.3.6.
    - If the vendor default account(s) will not be used, the account is removed or disabled.
  2.2.3: >
    Primary functions requiring different security levels are managed as follows:
    - Only one primary function exists on a system component,
    OR
    - Primary functions with differing security levels that exist on the same system component are isolated from each other,
    OR
    - Primary functions with differing security levels on the same system component are all secured to the level required by the function with the highest security need.
  2.2.4: >
    Only necessary services, protocols, daemons, and functions are enabled, and all unnecessary functionality is removed or disabled.
  2.2.5: >
    If any insecure services, protocols, or daemons are present:
    - Business justification is documented.
    - Additional security features are documented and implemented that reduce the risk of using insecure services, protocols, or daemons.
  2.2.6: System security parameters are configured to prevent misuse.
  2.2.7: All non-console administrative access is encrypted using strong cryptography.
  2.3: Wireless environments are configured and managed securely.
  2.3.1: >
    For wireless environments connected to the CDE or transmitting account data, all wireless vendor defaults are changed at installation or are confirmed to be secure, including but not limited to:
    - Default wireless encryption keys.
    - Passwords on wireless access points.
    - SNMP defaults.
    - Any other security-related wireless vendor defaults.
  2.3.2: >
    For wireless environments connected to the CDE or transmitting account data, wireless encryption keys are changed as follows:
    - Whenever personnel with knowledge of the key leave the company or the role for which the knowledge was necessary.
    - Whenever a key is suspected of or known to be compromised.
  3: Protect Stored Account Data
  3.1: Processes and mechanisms for protecting stored account data are defined and understood.
  3.1.1: >
    All security policies and operational procedures that are identified in Requirement 3 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  3.1.2: Roles and responsibilities for performing activities in Requirement 3 are documented, assigned, and understood.
  3.2: Storage of account data is kept to a minimum.
  3.2.1: >
    Account data storage is kept to a minimum through implementation of data retention and disposal policies, procedures, and processes that include at least the following:
    - Coverage for all locations of stored account data.
    - Coverage for any sensitive authentication data (SAD) stored prior to completion of authorization. This bullet is a best practice until its effective date; refer to Applicability Notes below for details.
    - Limiting data storage amount and retention time to that which is required for legal or regulatory, and/or business requirements.
    - Specific retention requirements for stored account data that defines length of retention period and includes a documented business justification.
    - Processes for secure deletion or rendering account data unrecoverable when no longer needed per the retention policy.
    - A process for verifying, at least once every three months, that stored account data exceeding the defined retention period has been securely deleted or rendered unrecoverable.
  3.3: Sensitive authentication data (SAD) is not stored after authorization.
  3.3.1: SAD is not retained after authorization, even if encrypted. All sensitive authentication data received is rendered unrecoverable upon completion of the authorization process.
  3.3.1.1: The full contents of any track are not retained upon completion of the authorization process.
  3.3.1.2: The card verification code is not retained upon completion of the authorization process.
  3.3.1.3: The personal identification number (PIN) and the PIN block are not retained upon completion of the authorization process.
  3.3.2: SAD that is stored electronically prior to completion of authorization is encrypted using strong cryptography.
  3.3.3: >
    Additional requirement for issuers and companies that support issuing services and store sensitive authentication data: Any storage of sensitive authentication data is:
    - Limited to that which is needed for a legitimate issuing business need and is secured.
    - Encrypted using strong cryptography. This bullet is a best practice until 31 March 2025, after which it will be required as part of Requirement 3.3.3 and must be fully considered during a PCI DSS assessment.
  3.4: Access to displays of full PAN and ability to copy PAN is restricted.
  3.4.1: PAN is masked when displayed (the BIN and last four digits are the maximum number of digits to be displayed), such that only personnel with a legitimate business need can see more than the BIN and last four digits of the PAN.
  3.4.2: >
    When using remote-access technologies, technical controls prevent copy and/or relocation of PAN for all personnel, except for those with documented, explicit authorization and a legitimate, defined business need.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  3.5: Primary account number (PAN) is secured wherever it is stored.
  3.5.1: >
    PAN is rendered unreadable anywhere it is stored by using any of the following approaches:
    - One-way hashes based on strong cryptography of the entire PAN.
    - Truncation (hashing cannot be used to replace the truncated segment of PAN).
    If hashed and truncated versions of the same PAN, or different truncation formats of the same PAN, are present in an environment,are in place such that the different versions cannot be correlated to reconstruct the original PAN.
    - Index tokens.
    - Strong cryptography with associated key-management processes and procedures.
  3.5.1.1: >
    Hashes used to render PAN unreadable (per the first bullet of Requirement 3.5.1) are keyed cryptographic hashes of the entire PAN, with associated key-management processes and procedures in accordance with Requirements 3.6 and 3.7.
    Note: This requirement is considered a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  3.5.1.2: >
    If disk-level or partition-level encryption (rather than file-, column-, or field-level database encryption) is used to render PAN unreadable, it is implemented only as follows:
    - On removable electronic media
    OR
    - If used for non-removable electronic media, PAN is also rendered unreadable via another mechanism that meets Requirement 3.5.1.
    Note: This requirement is considered a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment
  3.5.1.3: >
    If disk-level or partition-level encryption is used (rather than file-, column-, or field--level database encryption) to render PAN unreadable, it is managed as follows:
    - Logical access is managed separately and independently of native operating system authentication and access control mechanisms.
    - Decryption keys are not associated with user accounts.
    - Authentication factors (passwords, passphrases, or cryptographic keys) that allow access to unencrypted data are stored securely.
  3.6: Cryptographic keys used to protect stored account data are secured.
  3.6.1: >
    Procedures are defined and implemented to protect cryptographic keys used to protect stored account data against disclosure and misuse that include:
    - Access to keys is restricted to the fewest number of custodians necessary.
    - Key-encrypting keys are at least as strong as the data-encrypting keys they protect.
    - Key-encrypting keys are stored separately from data-encrypting keys.
    - Keys are stored securely in the fewest possible locations and forms.
  3.6.1.1: >
    Additional requirement for service providers only: A documented description of the cryptographic architecture is maintained that includes:
    - Details of all algorithms, protocols, and keys used for the protection of stored account data, including key strength and expiry date.
    - Preventing the use of the same cryptographic keys in production and test environments. This bullet is a best practice until its effective date; refer to
    Applicability Notes below for details.
      - Description of the key usage for each key.
      - Inventory of any hardware security modules (HSMs), key management systems (KMS), and other secure cryptographic devices (SCDs) used for key management, including type and location of devices, as outlined in Requirement 12.3.4.
  3.6.1.2: >
    Secret and private keys used to encrypt/decrypt stored account data are stored in one (or more) of the following forms at all times:
    - Encrypted with a key-encrypting key that is at least as strong as the data-encrypting key, and that is stored separately from the data-encrypting key.
    - Within a secure cryptographic device (SCD), such as a hardware security module (HSM) or PTS-approved point-of-interaction device.
    - As at least two full-length key components or key shares, in accordance with an industry-accepted method.
  3.6.1.3: Access to cleartext cryptographic key components is restricted to the fewest number of custodians necessary.
  3.6.1.4: Cryptographic keys are stored in the fewest possible locations.
  3.7: Where cryptography is used to protect stored account data, key management processes and procedures covering all aspects of the key lifecycle are defined and implemented.
  3.7.1: Key-management policies and procedures are implemented to include generation of strong cryptographic keys used to protect stored account data.
  3.7.2: Key-management policies and procedures are implemented to include secure distribution of cryptographic keys used to protect stored account data.
  3.7.3: Key-management policies and procedures are implemented to include secure storage of cryptographic keys used to protect stored account data.
  3.7.4: >
    Key management policies and procedures are implemented for cryptographic key changes for keys that have reached the end of their cryptoperiod, as defined by the associated application vendor or key owner, and based on industry best practices and guidelines, including the following:
    - A defined cryptoperiod for each key type in use.
    - A process for key changes at the end of the defined cryptoperiod.
  3.7.5: >
    Key management policies procedures are implemented to include the retirement, replacement, or destruction of keys used to protect stored account data, as deemed necessary when:
    - The key has reached the end of its defined cryptoperiod.
    - The integrity of the key has been weakened, including when personnel with knowledge of a cleartext key component leaves the company, or the role for which the key component was known.
    - The key is suspected of or known to be compromised.
    - Retired or replaced keys are not used for encryption operations.
  3.7.6: Where manual cleartext cryptographic key-management operations are performed by personnel, key-management policies and procedures are implemented include managing these operations using split knowledge and dual control.
  3.7.7: Key management policies and procedures are implemented to include the prevention of unauthorized substitution of cryptographic keys.
  3.7.8: Key management policies and procedures are implemented to include that cryptographic key custodians formally acknowledge (in writing or electronically) that they understand and accept their key-custodian responsibilities.
  3.7.9: >
    Additional requirement for service providers only: Where a service provider shares cryptographic keys with its customers for transmission or storage of account data, guidance on secure transmission, storage and updating of such keys is documented and distributed to the service provider's customers.
  4: Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks
  4.1: Processes and mechanisms for protecting cardholder data with strong cryptography during transmission over open, public networks are defined and documented.
  4.1.1: >
    All security policies and operational procedures that are identified in Requirement 4 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  4.1.2: Roles and responsibilities for performing activities in Requirement 4 are documented, assigned, and understood.
  4.2: PAN is protected with strong cryptography during transmission.
  4.2.1: >
    Strong cryptography and security protocols are implemented as follows to safeguard PAN during transmission over open, public networks:
    - Only trusted keys and certificates are accepted.
    - Certificates used to safeguard PAN during transmission over open, public networks are confirmed as valid and are not expired or revoked. This bullet is a best practice until 31 March 2025, after which it will be required as part of Requirement 4.2.1 and must be fully considered during a PCI DSS assessment.
    - The protocol in use supports only secure versions or configurations and does not support fallback to, or use of insecure versions, algorithms, key sizes, or implementations.
    - The encryption strength is appropriate for the encryption methodology in use.
  4.2.1.1: >
    An inventory of the entity's trusted keys and certificates used to protect PAN during transmission is maintained.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  4.2.1.2: >
    Wireless networks transmitting PAN or connected to the CDE use industry best practices to implement strong cryptography for authentication and transmission.
  4.2.2: PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies.
  5: Protect All Systems and Networks from Malicious Software
  5.1: Processes and mechanisms for protecting all systems and networks from malicious software are defined and understood.
  5.1.1: >
    All security policies and operational procedures that are identified in Requirement 5 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  5.1.2: Roles and responsibilities for performing activities in Requirement 5 are documented, assigned, and understood.
  5.2: Malicious software (malware) is prevented or detected and addressed.
  5.2.1: >
    An anti-malware solution(s) is deployed on all system components, except for those system components identified in periodic evaluations per Requirement 5.2.3 that concludes the system components are not at risk from malware.
  5.2.2: >
    The deployed anti-malware solution(s):
    - Detects all known types of malware.
    - Removes, blocks, or contains all known types of malware.
  5.2.3: >
    Any system components that are not at risk for malware are evaluated periodically to include the following:
    - A documented list of all system components not at risk for malware.
    - Identification and evaluation of evolving malware threats for those system components.
    - Confirmation whether such system components continue to not require anti-malware protection.
  5.2.3.1: >
    The frequency of periodic evaluations of system components identified as not at risk for malware is defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  5.3: Anti-malware mechanisms and processes are active, maintained, and monitored.
  5.3.1: The anti-malware solution(s) is kept current via automatic updates.
  5.3.2: >
    The anti-malware solution(s):
    - Performs periodic scans and active or real-time scans.
    OR
    - Performs continuous behavioral analysis of systems or processes.
  5.3.2.1: >
    If periodic malware scans are performed to meet Requirement 5.3.2, the frequency of scans is defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  5.3.3: >
    For removable electronic media, the anti-malware solution(s):
    - Performs automatic scans of when the media is inserted, connected, or logically mounted,
    OR
    - Performs continuous behavioral analysis of systems or processes when the media is inserted, connected, or logically mounted.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  5.3.4: Audit logs for the anti-malware solution(s) are enabled and retained in accordance with Requirement 10.5.1.
  5.3.5: Anti-malware mechanisms cannot be disabled or altered by users, unless specifically documented, and authorized by management on a case-by-case basis for a limited time period.
  5.4: Anti-phishing mechanisms protect users against phishing attacks.
  5.4.1: >
    Processes and automated mechanisms are in place to detect and protect personnel against phishing attacks.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  6: Develop and Maintain Secure Systems and Software
  6.1: Processes and mechanisms for developing and maintaining secure systems and software are defined and understood.
  6.1.1: >
    All security policies and operational procedures that are identified in Requirement 6 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  6.1.2: Roles and responsibilities for performing activities in Requirement 6 are documented, assigned, and understood.
  6.2: Bespoke and custom software are developed securely.
  6.2.1: >
    Bespoke and custom software are developed securely, as follows:
    - Based on industry standards and/or best practices for secure development.
    - In accordance with PCI DSS (for example, secure authentication and logging).
    - Incorporating consideration of information security issues during each stage of the software development lifecycle.
  6.2.2: >
    Software development personnel working on bespoke and custom software are trained at least once every 12 months as follows:
    - On software security relevant to their job function and development languages.
    - Including secure software design and secure coding techniques.
    - Including, if security testing tools are used, how to use the tools for detecting vulnerabilities in software.
  6.2.3: >
    Bespoke and custom software is reviewed prior to being released into production or to customers, to identify and correct potential coding vulnerabilities, as follows:
    - Code reviews ensure code is developed according to secure coding guidelines.
    - Code reviews look for both existing and emerging software vulnerabilities.
    - Appropriate corrections are implemented prior to release.
  6.2.3.1: >
    If manual code reviews are performed for bespoke and custom software prior to release to production, code changes are:
    - Reviewed by individuals other than the originating code author, and who are knowledgeable about code-review techniques and secure coding practices.
    - Reviewed and approved by management prior to release.
  6.2.4: >
    Software engineering techniques or other methods are defined and in use by software development personnel to prevent or mitigate common software attacks and related vulnerabilities in bespoke and custom software, including but not limited to the following:
    - Injection attacks, including SQL, LDAP, XPath, or other command, parameter, object, fault, or injection-type flaws.
    - Attacks on data and data structures, including attempts to manipulate buffers, pointers, input data, or shared data.
    - Attacks on cryptography usage, including attempts to exploit weak, insecure, or inappropriate cryptographic implementations, algorithms, cipher suites, or modes of operation.
    - Attacks on business logic, including attempts to abuse or bypass application features and functionalities through the manipulation of APIs, communication protocols and channels, client-side functionality, or other system/application functions and resources. This includes cross-site scripting (XSS) and cross-site request forgery (CSRF).
    - Attacks on access control mechanisms, including attempts to bypass or abuse identification, authentication, or authorization mechanisms, or attempts to exploit weaknesses in the implementation of such mechanisms.
    - Attacks via any "high-risk" vulnerabilities identified in the vulnerability identification process, as defined in Requirement 6.3.1.
  6.3: Security vulnerabilities are identified and addressed.
  6.3.1: >
    Security vulnerabilities are identified and managed as follows:
    - New security vulnerabilities are identified using industry-recognized sources for security vulnerability information, including alerts from internationalnational computer emergency response teams (CERTs).
    - Vulnerabilities are assigned a risk ranking based on industry best practices and consideration of potential impact.
    - Risk rankings identify, at a minimum, all vulnerabilities considered to be a high-risk or critical to the environment.
    - Vulnerabilities for bespoke and custom, and third-party software (for example operating systems and databases) are covered.
  6.3.2: >
    An inventory of bespoke and custom software, and third-party software components incorporated into bespoke and custom software is maintained to facilitate vulnerability and patch management.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  6.3.3: >
    All system components are protected from known vulnerabilities by installing applicable security patches/updates as follows:
    - Critical or high-security patches/updates (identified according to the risk ranking process at Requirement 6.3.1) are installed within one month of release.
    - All other applicable security patches/updates are installed within an appropriate time frame as determined by the entity (for example, within three months of release).
  6.4: Public-facing web applications are protected against attacks.
  6.4.1: >
    For public-facing web applications, new threats and vulnerabilities are addressed on an ongoing basis and these applications are protected against known attacks as follows:
    - Reviewing public-facing web applications via manual or automated application vulnerability security assessment tools or methods as follows:
    - At least once every 12 months and after significant changes.
    - By an entity that specializes in application security.
    - Including, at a minimum, all common software attacks in Requirement 6.2.4.
    - All vulnerabilities are ranked in accordance with requirement 6.3.1.
    - All vulnerabilities are corrected.
    - The application is re-evaluated after the corrections
    OR
    - Installing an automated technical solution(s) that continually detects and prevents web-based attacks as follows:
    - Installed in front of public-facing web applications to detect and prevent web-based attacks.
    - Actively running and up to date as applicable.
    - Generating audit logs.
    - Configured to either block web-based attacks or generate an alert that is immediately investigated.
    Note: This requirement will be superseded by Requirement 6.4.2 after 31 March 2025 when Requirement 6.4.2 becomes effective.
  6.4.2: >
    For public-facing web applications, an automated technical solution is deployed that continually detects and prevents web-based attacks, with at least the following:
    - Is installed in front of public-facing web applications and is configured to detect and prevent web-based attacks.
    - Actively running and up to date as applicable.
    - Generating audit logs.
    - Configured to either block web-based attacks or generate an alert that is immediately investigated.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment. This new requirement will replace Requirement 6.4.1 once its effective date is reached.
  6.4.3: >
    All payment page scripts that are loaded and executed in the consumer's browser are managed as follows:
    - A method is implemented to confirm that each script is authorized.
    - A method is implemented to assure the integrity of each script.
    - An inventory of all scripts is maintained with written justification as to why each is necessary.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  6.5: Changes to all system components are managed securely.
  6.5.1: >
    Changes to all system components in the production environment are made according to established procedures that include:
    - Reason for, and description of, the change.
    - Documentation of security impact.
    - Documented change approval by authorized parties.
    - Testing to verify that the change does not adversely impact system security.
    - For bespoke and custom software changes, all updates are tested for compliance with Requirement 6.2.4 before being deployed into production.
    - Procedures to address failures and return to a secure state.
  6.5.2: Upon completion of a significant change, all applicable PCI DSS requirements are confirmed to be in place on all new or changed systems and networks, and documentation is updated as applicable.
  6.5.3: Pre-production environments are separated from production environments and the separation is enforced with access controls.
  6.5.4: Roles and functions are separated between production and pre-production environments to provide accountability such that only reviewed and approved changes are deployed.
  6.5.5: Live PANs are not used in pre-production environments, except where those environments are included in the CDE and protected in accordance with all applicable PCI DSS requirements.
  6.5.6: Test data and test accounts are removed from system components before the system goes into production.
  7: Restrict Access to System Components and Cardholder Data by Business Need to Know
  7.1: Processes and mechanisms for restricting access to system components and cardholder data by business need to know are defined and understood.
  7.1.1: >
    All security policies and operational procedures that are identified in Requirement 7 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  7.1.2: Roles and responsibilities for performing activities in Requirement 7 are documented, assigned, and understood.
  7.2: Access to system components and data is appropriately defined and assigned.
  7.2.1: >
    An access control model is defined and includes granting access as follows:
    - Appropriate access depending on the entity's business and access needs.
    - Access to system components and data resources that is based on users' job classification and functions.
    - The least privileges required (for example, user, administrator) to perform a job function.
  7.2.2: >
    Access is assigned to users, including privileged users, based on:
    - Job classification and function.
    - Least privileges necessary to perform job responsibilities.
  7.2.3: Required privileges are approved by authorized personnel.
  7.2.4: >
    All user accounts and related access privileges, including third-party/vendor accounts, are reviewed as follows:
    - At least once every six months.
    - To ensure user accounts and access remain appropriate based on job function.
    - Any inappropriate access is addressed.
    - Management acknowledges that access remains appropriate.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  7.2.5: >
    All application and system accounts and related access privileges are assigned and managed as follows:
    - Based on the least privileges necessary for the operability of the system or application.
    - Access is limited to the systems, applications, or processes that specifically require their use.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  7.2.5.1: >
    All access by application and system accounts and related access privileges are reviewed as follows:
    - Periodically (at the frequency defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1).
    - The application/system access remains appropriate for the function being performed.
    - Any inappropriate access is addressed.
    - Management acknowledges that access remains appropriate.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  7.2.6: >
    All user access to query repositories of stored cardholder data is restricted as follows:
    - Via applications or other programmatic methods, with access and allowed actions based on user roles and least privileges.
    - Only the responsible administrator(s) can directly access or query repositories of stored CHD.
  7.3: Access to system components and data is managed via an access control system(s).
  7.3.1: An access control system(s) is in place that restricts access based on a user's need to know and covers all system components.
  7.3.2: The access control system(s) is configured to enforce permissions assigned to individuals, applications, and systems based on job classification and function.
  7.3.3: The access control system(s) is set to \u201cdeny all\u201d by default.
  8: Identify Users and Authenticate Access to System Components
  8.1: Processes and mechanisms for identifying users and authenticating access to system components are defined and understood.
  8.1.1: >
    All security policies and operational procedures that are identified in Requirement 8 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  8.1.2: Roles and responsibilities for performing activities in Requirement 8 are documented, assigned, and understood.
  8.2: User identification and related accounts for users and administrators are strictly managed throughout an account's lifecycle.
  8.2.1: All users are assigned a unique ID before access to system components or cardholder data is allowed.
  8.2.2: >
    Group, shared, or generic accounts, or other shared authentication credentials are only used when necessary on an exception basis, and are managed as follows:
    - Account use is prevented unless needed for an exceptional circumstance.
    - Use is limited to the time needed for the exceptional circumstance.
    - Business justification for use is documented.
    - Use is explicitly approved by management.
    - Individual user identity is confirmed before access to an account is granted.
    - Every action taken is attributable to an individual user.
  8.2.3: >
    Additional requirement for service providers only: Service providers with remote access to customer premises use unique authentication factors for each customer premises.
  8.2.4: >
    Addition, deletion, and modification of user IDs, authentication factors, and other identifier objects are managed as follows:
    - Authorized with the appropriate approval.
    - Implemented with only the privileges specified on the documented approval.
  8.2.5: Access for terminated users is immediately revoked.
  8.2.6: Inactive user accounts are removed or disabled within 90 days of inactivity.
  8.2.7: >
    Accounts used by third parties to access, support, or maintain system components via remote access are managed as follows:
    - Enabled only during the time period needed and disabled when not in use.
    - Use is monitored for unexpected activity.
  8.2.8: If a user session has been idle for more than 15 minutes, the user is required to re-authenticate to re-activate the terminal or session.
  8.3: Strong authentication for users and administrators is established and managed.
  8.3.1: >
    All user access to system components for users and administrators is authenticated via at least one of the following authentication factors:
    - Something you know, such as a password or passphrase.
    - Something you have, such as a token device or smart card.
    - Something you are, such as a biometric element.
  8.3.2: Strong cryptography is used to render all authentication factors unreadable during transmission and storage on all system components.
  8.3.3: User identity is verified before modifying any authentication factor.
  8.3.4: >
    Invalid authentication attempts are limited by:
    - Locking out the user ID after not more than 10 attempts.
    - Setting the lockout duration to a minimum of 30 minutes or until the user's identity is confirmed.
  8.3.5: >
    If passwords/passphrases are used as authentication factors to meet Requirement 8.3.1, they are set and reset for each user as follows:
    - Set to a unique value for first-time use and upon reset.
    - Forced to be changed immediately after the first use.
  8.3.6: >
    If passwords/passphrases are used as authentication factors to meet Requirement 8.3.1, they meet the following minimum level of complexity:
    - A minimum length of 12 characters (or IF the system does not support 12 characters, a minimum length of eight characters).
    - Contain both numeric and alphabetic characters.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment. Until 31 March 2025, passwords must be a minimum length of seven characters in accordance with PCI DSS v3.2.1 Requirement 8.2.3.
  8.3.7: Individuals are not allowed to submit a new password/passphrase that is the same as any of the last four passwords/passphrases used.
  8.3.8: >
    Authentication policies and procedures are documented and communicated to all users including:
    - Guidance on selecting strong authentication factors.
    - Guidance for how users should protect their authentication factors.
    - Instructions not to reuse previously used passwords/passphrases.
    - Instructions to change passwords/passphrases if there is any suspicion or knowledge that the password/passphrases have been compromised and how to report the incident.
  8.3.9: >
    If passwords/passphrases are used as the only authentication factor for user access (i.e., in any single-factor authentication implementation) then either:
    - Passwords/passphrases are changed at least once every 90 days,
    OR
    - The security posture of accounts is dynamically analyzed, and real-time access to resources is automatically determined accordingly.
  8.3.10: >
    Additional requirement for service providers only: If passwords/passphrases are used as the only authentication factor for customer user access to cardholder data (i.e., in any single-factor authentication implementation), then guidance is provided to customer users including:
    - Guidance for customers to change their user passwords/passphrases periodically.
    - Guidance as to when, and under what circumstances, passwords/passphrases are to be changed.
    Note: This requirement for service providers will be superseded by Requirement 8.3.10.1 as of 31 March 2025.
  8.3.10.1: >
    Additional requirement for service providers only: If passwords/passphrases are used as the only authentication factor for customer user access (i.e., in any single-factor authentication implementation) then either:
    - Passwords/passphrases are changed at least once every 90 days,
    OR
    - The security posture of accounts is dynamically analyzed, and real-time access to resources is automatically determined accordingly.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment. Until this requirement is effective on 31 March 2025, service providers may meet either Requirement 8.3.10 or 8.3.10.1.
  8.3.11: >
    Where authentication factors such as physical or logical security tokens, smart cards, or certificates are used:
    - Factors are assigned to an individual user and not shared among multiple users.
    - Physical and/or logical controls ensure only the intended user can use that factor to gain access.
  8.4: Multi-factor authentication (MFA) is implemented to secure access into the CDE.
  8.4.1: MFA is implemented for all non-console access into the CDE for personnel with administrative access.
  8.4.2: >
    MFA is implemented for all access into the CDE.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  8.4.3: >
    MFA is implemented for all remote network access originating from outside the entity's network that could access or impact the CDE as follows:
    - All remote access by all personnel, both users and administrators, originating from outside the entity's network.
    - All remote access by third parties and vendors.
  8.5: Multi-factor authentication (MFA) systems are configured to prevent misuse.
  8.5.1: >
    MFA systems are implemented as follows:
    - The MFA system is not susceptible to replay attacks.
    - MFA systems cannot be bypassed by any users, including administrative users unless specifically documented, and authorized by management on an exception basis, for a limited time period.
    - At least two different types of authentication factors are used.
    - Success of all authentication factors is required before access is granted.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  8.6: Use of application and system accounts and associated authentication factors is strictly managed.
  8.6.1: >
    If accounts used by systems or applications can be used for interactive login, they are managed as follows:
    - Interactive use is prevented unless needed for an exceptional circumstance.
    - Interactive use is limited to the time needed for the exceptional circumstance.
    - Business justification for interactive use is documented.
    - Interactive use is explicitly approved by management.
    - Individual user identity is confirmed before access to account is granted.
    - Every action taken is attributable to an individual user.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  8.6.2: >
    Passwords/passphrases for any application and system accounts that can be used for interactive login are not hard coded in scripts, configuration/property files, or bespoke and custom source code.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  8.6.3: >
    Passwords/passphrases for any application and system accounts are protected against misuse as follows:
    - Passwords/passphrases are changed periodically (at the frequency defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1) and upon suspicion or confirmation of compromise.
    - Passwords/passphrases are constructed with sufficient complexity appropriate for how frequently the entity changes the passwords/passphrases.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  9: Restrict Physical Access to Cardholder Data
  9.1: Processes and mechanisms for restricting physical access to cardholder data are defined and understood.
  9.1.1: >
    All security policies and operational procedures that are identified in Requirement 9 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  9.1.2: Roles and responsibilities for performing activities in Requirement 9 are documented, assigned, and understood.
  9.2: Physical access controls manage entry into facilities and systems containing cardholder data.
  9.2.1: Appropriate facility entry controls are in place to restrict physical access to systems in the CDE.
  9.2.1.1: >
    Individual physical access to sensitive areas within the CDE is monitored with either video cameras or physical access control mechanisms (or both) as follows:
    - Entry and exit points to/from sensitive areas within the CDE are monitored.
    - Monitoring devices or mechanisms are protected from tampering or disabling.
    - Collected data is reviewed and correlated with other entries.
    - Collected data is stored for at least three months, unless otherwise restricted by law.
  9.2.2: Physical and/or logical controls are implemented to restrict use of publicly accessible network jacks within the facility.
  9.2.3: Physical access to wireless access points, gateways, networking/communications hardware, and telecommunication lines within the facility is restricted.
  9.2.4: Access to consoles in sensitive areas is restricted via locking when not in use.
  9.3: Physical access for personnel and visitors is authorized and managed.
  9.3.1: >
    Procedures are implemented for authorizing and managing physical access of personnel to the CDE, including:
    - Identifying personnel.
    - Managing changes to an individual's physical access requirements.
    - Revoking or terminating personnel identification.
    - Limiting access to the identification process or system to authorized personnel.
  9.3.1.1: >
    Physical access to sensitive areas within the CDE for personnel is controlled as follows:
    - Access is authorized and based on individual job function.
    - Access is revoked immediately upon termination.
    - All physical access mechanisms, such as keys, access cards, etc., are returned or disabled upon termination.
  9.3.2: >
    Procedures are implemented for authorizing and managing visitor access to the CDE, including:
    - Visitors are authorized before entering.
    - Visitors are escorted at all times.
    - Visitors are clearly identified and given a badge or other identification that expires.
    - Visitor badges or other identification visibly distinguishes visitors from personnel.
  9.3.3: Visitor badges or identification are surrendered or deactivated before visitors leave the facility or at the date of expiration.
  9.3.4: >
    A visitor log is used to maintain a physical record of visitor activity within the facility and within sensitive areas, including:
    - The visitor's name and the organization represented.
    - The date and time of the visit.
    - The name of the personnel authorizing physical access.
    - Retaining the log for at least three months, unless otherwise restricted by law.
  9.4: Media with cardholder data is securely stored, accessed, distributed, and destroyed.
  9.4.1: All media with cardholder data is physically secured.
  9.4.1.1: Offline media backups with cardholder data are stored in a secure location.
  9.4.1.2: The security of the offline media backup location(s) with cardholder data is reviewed at least once every 12 months.
  9.4.2: All media with cardholder data is classified in accordance with the sensitivity of the data.
  9.4.3: >
    Media with cardholder data sent outside the facility is secured as follows:
    - Media sent outside the facility is logged.
    - Media is sent by secured courier or other delivery method that can be accurately tracked.
    - Offsite tracking logs include details about media location.
  9.4.4: Management approves all media with cardholder data that is moved outside the facility (including when media is distributed to individuals).
  9.4.5: Inventory logs of all electronic media with cardholder data are maintained.
  9.4.5.1: Inventories of electronic media with cardholder data are conducted at least once every 12 months.
  9.4.6: >
    Hard-copy materials with cardholder data are destroyed when no longer needed for business or legal reasons, as follows:
    - Materials are cross-cut shredded, incinerated, or pulped so that cardholder data cannot be reconstructed.
    - Materials are stored in secure storage containers prior to destruction.
  9.4.7: >
    Electronic media with cardholder data is destroyed when no longer needed for business or legal reasons via one of the following:
    - The electronic media is destroyed.
    - The cardholder data is rendered unrecoverable so that it cannot be reconstructed.
  9.5: Point-of-interaction (POI) devices are protected from tampering and unauthorized substitution.
  9.5.1: >
    POI devices that capture payment card data via direct physical interaction with the payment card form factor are protected from tampering and unauthorized substitution, including the following:
    - Maintaining a list of POI devices.
    - Periodically inspecting POI devices to look for tampering or unauthorized substitution.
    - Training personnel to be aware of suspicious behavior and to report tampering or unauthorized substitution of devices.
  9.5.1.1: >
    An up-to-date list of POI devices is maintained, including:
    - Make and model of the device.
    - Location of device.
    - Device serial number or other methods of unique identification.
  9.5.1.2: >
    POI device surfaces are periodically inspected to detect tampering and unauthorized substitution.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  9.5.1.2.1: The frequency of periodic POI device inspections and the type of inspections performed is defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1.
  9.5.1.3: >
    Training is provided for personnel in POI environments to be aware of attempted tampering or replacement of POI devices, and includes:
    - Verifying the identity of any third-party persons claiming to be repair or maintenance personnel, before granting them access to modify or troubleshoot devices.
    - Procedures to ensure devices are not installed, replaced, or returned without verification.
    - Being aware of suspicious behavior around devices.
    - Reporting suspicious behavior and indications of device tampering or substitution to appropriate personnel.
  10: Log and Monitor All Access to System Components and Cardholder Data
  10.1: Processes and mechanisms for logging and monitoring all access to system components and cardholder data are defined and documented.
  10.1.1: >
    All security policies and operational procedures that are identified in Requirement 10 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  10.1.2: Roles and responsibilities for performing activities in Requirement 10 are documented, assigned, and understood.
  10.2: Audit logs are implemented to support the detection of anomalies and suspicious activity, and the forensic analysis of events.
  10.2.1: Interview the system administrator and examine system configurations to verify that audit logs are enabled and active for all system components.
  10.2.1.1: Audit logs capture all individual user access to cardholder data.
  10.2.1.2: Audit logs capture all actions taken by any individual with administrative access, including any interactive use of application or system accounts.
  10.2.1.3: Audit logs capture all access to audit logs.
  10.2.1.4: Audit logs capture all invalid logical access attempts.
  10.2.1.5: >
    Audit logs capture all changes to identification and authentication credentials including, but not limited to:
    - Creation of new accounts.
    - Elevation of privileges.
    - All changes, additions, or deletions to accounts with administrative access.
  10.2.1.6: >
    Audit logs capture the following:
    - All initialization of new audit logs, and
    - All starting, stopping, or pausing of the existing audit logs.
  10.2.1.7: Audit logs capture all creation and deletion of system-level objects.
  10.2.2: >
    Audit logs record the following details for each auditable event:
    - User identification.
    - Type of event.
    - Date and time.
    - Success and failure indication.
    - Origination of event.
    - Identity or name of affected data, system component, resource, or service (for example, name and protocol).
  10.3: Audit logs are protected from destruction and unauthorized modifications.
  10.3.1: Read access to audit logs files is limited to those with a job-related need.
  10.3.2: Audit log files are protected to prevent modifications by individuals.
  10.3.3: Audit log files, including those for external-facing technologies, are promptly backed up to a secure, central, internal log server(s) or other media that is difficult to modify.
  10.3.4: File integrity monitoring or change-detection mechanisms is used on audit logs to ensure that existing log data cannot be changed without generating alerts.
  10.4: Audit logs are reviewed to identify anomalies or suspicious activity.
  10.4.1: >
    The following audit logs are reviewed at least once daily:
    - All security events.
    - Logs of all system components that store, process, or transmit CHD and/or SAD.
    - Logs of all critical system components.
    - Logs of all servers and system components that perform security functions (for example, network security controls, intrusion-detection systems/intrusion-prevention systems (IDS/IPS), authentication servers).
  10.4.1.1: >
    Automated mechanisms are used to perform audit log reviews.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  10.4.2: Logs of all other system components (those not specified in Requirement 10.4.1) are reviewed periodically.
  10.4.2.1: >
    The frequency of periodic log reviews for all other system components (not defined in Requirement 10.4.1) is defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  10.4.3: Exceptions and anomalies identified during the review process are addressed.
  10.5: Audit log history is retained and available for analysis.
  10.5.1: Retain audit log history for at least 12 months, with at least the most recent three months immediately available for analysis.
  10.6: Time-synchronization mechanisms support consistent time settings across all systems.
  10.6.1: System clocks and time are synchronized using time-synchronization technology.
  10.6.2: >
    Systems are configured to the correct and consistent time as follows:
    - One or more designated time servers are in use.
    - Only the designated central time server(s) receives time from external sources.
    - Time received from external sources is based on International Atomic Time or Coordinated Universal Time (UTC).
    - The designated time server(s) accept time updates only from specific industry-accepted external sources.
    - Where there is more than one designated time server, the time servers peer with one another to keep accurate time.
    - Internal systems receive time information only from designated central time server(s).
  10.6.3: >
    Time synchronization settings and data are protected as follows:
    - Access to time data is restricted to only personnel with a business need.
    - Any changes to time settings on critical systems are logged, monitored, and reviewed.
  10.7: Failures of critical security control systems are detected, reported, and responded to promptly.
  10.7.1: >
    Additional requirement for service providers only: Failures of critical security control systems are detected, alerted, and addressed promptly, including but not limited to failure of the following critical security control systems:
    - Network security controls.
    - IDS/IPS.
    - FIM.
    - Anti-malware solutions.
    - Physical access controls.
    - Logical access controls.
    - Audit logging mechanisms.
    - Segmentation controls (if used).
    Note: This requirement will be superseded by Requirement 10.7.2 as of 31 March 2025.
  10.7.2: >
    Failures of critical security control systems are detected, alerted, and addressed promptly, including but not limited to failure of the following critical security control systems:
    - Network security controls.
    - IDS/IPS.
    - Change-detection mechanisms.
    - Anti-malware solutions.
    - Physical access controls.
    - Logical access controls.
    - Audit logging mechanisms.
    - Segmentation controls (if used).
    - Audit log review mechanisms.
    - Automated security testing tools (if used).
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment and will supersede Requirement 10.7.1.
  10.7.3: >
    Failures of any critical security controls systems are responded to promptly, including but not limited to:
    - Restoring security functions.
    - Identifying and documenting the duration (date and time from start to end) of the security failure.
    - Identifying and documenting the cause(s) of failure and documenting required remediation.
    - Identifying and addressing any security issues that arose during the failure.
    - Determining whether further actions are required as a result of the security failure.
    - Implementing controls to prevent the cause of failure from reoccurring.
    - Resuming monitoring of security controls.
    Note: This is a current v3.2.1 requirement that applies to service providers only. However, this requirement is a best practice for all other entities until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  11: Test Security of Systems and Networks Regularly
  11.1: Processes and mechanisms for regularly testing security of systems and networks are defined and understood.
  11.1.1: >
    All security policies and operational procedures that are identified in Requirement 11 are:
    - Documented.
    - Kept up to date.
    - In use.
    - Known to all affected parties.
  11.1.2: Roles and responsibilities for performing activities in Requirement 11 are documented, assigned, and understood.
  11.2: Wireless access points are identified and monitored, and unauthorized wireless access points are addressed.
  11.2.1: >
    Authorized and unauthorized wireless access points are managed as follows:
    - The presence of wireless (Wi-Fi) access points is tested for,
    - All authorized and unauthorized wireless access points are detected and identified,
    - Testing, detection, and identification occurs at least once every three months.
    - If automated monitoring is used, personnel are notified via generated alerts.
  11.2.2: An inventory of authorized wireless access points is maintained, including a documented business justification.
  11.3: External and internal vulnerabilities are regularly identified, prioritized, and addressed.
  11.3.1: >
    Internal vulnerability scans are performed as follows:
    - At least once every three months.
    - High-risk and critical vulnerabilities (per the entity's vulnerability risk rankings defined at Requirement 6.3.1) are resolved.
    - Rescans are performed that confirm all high-risk and critical vulnerabilities (as noted above) have been resolved.
    - Scan tool is kept up to date with latest vulnerability information.
    - Scans are performed by qualified personnel and organizational independence of the tester exists.
  11.3.1.1: >
    All other applicable vulnerabilities (those not ranked as high-risk or critical per the entity's vulnerability risk rankings defined at Requirement 6.3.1) are managed as follows:
    - Addressed based on the risk defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1.
    - Rescans are conducted as needed.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  11.3.1.2: >
    Internal vulnerability scans are performed via authenticated scanning as follows:
    - Systems that are unable to accept credentials for authenticated scanning are documented.
    - Sufficient privileges are used for those systems that accept credentials for scanning.
    - If accounts used for authenticated scanning can be used for interactive login, they are managed in accordance with Requirement 8.2.2.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  11.3.1.3: >
    Internal vulnerability scans are performed after any significant change as follows:
    - High-risk and critical vulnerabilities (per the entity's vulnerability risk rankings defined at Requirement 6.3.1) are resolved.
    - Rescans are conducted as needed.
    - Scans are performed by qualified personnel and organizational independence of the tester exists (not required to be a QSA or ASV).
  11.3.2: >
    External vulnerability scans are performed as follows:
    - At least once every three months.
    - By PCI SSC Approved Scanning Vendor (ASV).
    - Vulnerabilities are resolved and ASV Program Guide requirements for a passing scan are met.
    - Rescans are performed as needed to confirm that vulnerabilities are resolved per the ASV Program Guide requirements for a passing scan.
  11.3.2.1: >
    External vulnerability scans are performed after any significant change as follows:
    - Vulnerabilities that are scored 4.0 or higher by the CVSS are resolved.
    - Rescans are conducted as needed.
    - Scans are performed by qualified personnel and organizational independence of the tester exists (not required to be a QSA or ASV).
  11.4: External and internal penetration testing is regularly performed, and exploitable vulnerabilities and security weaknesses are corrected.
  11.4.1: >
    A penetration testing methodology is defined, documented, and implemented by the entity and includes:
    - Industry-accepted penetration testing approaches.
    - Coverage for the entire CDE perimeter and critical systems.
    - Testing from both inside and outside the network.
    - Testing to validate any segmentation and scope-reduction controls.
    - Application-layer penetration testing to identify, at a minimum, the vulnerabilities listed in Requirement 6.2.4.
    - Network-layer penetration tests that encompass all components that support network functions as well as operating systems.
    - Review and consideration of threats and vulnerabilities experienced in the last 12 months.
    - Documented approach to assessing and addressing the risk posed by exploitable vulnerabilities and security weaknesses found during penetration testing.
    - Retention of penetration testing results and remediation activities results for at least 12 months.
  11.4.2: >
    Internal penetration testing is performed:
    - Per the entity's defined methodology
    - At least once every 12 months
    - After any significant infrastructure or application upgrade or change
    - By a qualified internal resource or qualified external third-party
    - Organizational independence of the tester exists (not required to be a QSA or ASV)
  11.4.3: >
    External penetration testing is performed:
    - Per the entity's defined methodology
    - At least once every 12 months
    - After any significant infrastructure or application upgrade or change
    - By a qualified internal resource or qualified external third party
    - Organizational independence of the tester exists (not required to be a QSA or ASV)
  11.4.4: >
    Exploitable vulnerabilities and security weaknesses found during penetration testing are corrected as follows:
    - In accordance with the entity's assessment of the risk posed by the security issue as defined in Requirement 6.3.1.
    - Penetration testing is repeated to verify the corrections.
  11.4.5: >
    If segmentation is used to isolate the CDE from other networks, penetration tests are performed on segmentation controls as follows:
    - At least once every 12 months and after any changes to segmentation controls/methods
    - Covering all segmentation controls/methods in use
    - According to the entity's defined penetration testing methodology
    - Confirming that the segmentation controls/methods are operational and effective, and isolate the CDE from all out-of-scope systems
    - Confirming effectiveness of any use of isolation to separate systems with differing security levels (see Requirement 2.2.3)
    - Performed by a qualified internal resource or qualified external third party
    - Organizational independence of the tester exists (not required to be a QSA or ASV)
  11.4.6: >
    Additional requirement for service providers only: If segmentation is used to isolate the CDE from other networks, penetration tests are performed on segmentation controls as follows:
    - At least once every six months and after any changes to segmentation controls/methods.
    - Covering all segmentation controls/methods in use.
    - According to the entity's defined penetration testing methodology.
    - Confirming that the segmentation controls/methods are operational and effective, and isolate the CDE from all out-of-scope systems.
    - Confirming effectiveness of any use of isolation to separate systems with differing security levels (see Requirement 2.2.3).
    - Performed by a qualified internal resource or qualified external third party.
    - Organizational independence of the tester exists (not required to be a QSA or ASV).
  11.4.7: >
    Additional requirement for multi-tenant service providers only: Multi-tenant service providers support their customers for external penetration testing per Requirement 11.4.3 and 11.4.4.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  11.5: Network intrusions and unexpected file changes are detected and responded to.
  11.5.1: >
    Intrusion-detection and/or intrusion-prevention techniques are used to detect and/or prevent intrusions into the network as follows:
    - All traffic is monitored at the perimeter of the CDE.
    - All traffic is monitored at critical points in the CDE.
    - Personnel are alerted to suspected compromises.
    - All intrusion-detection and prevention engines, baselines, and signatures are kept up to date.
  11.5.1.1: >
    Additional requirement for service providers only: Intrusion-detection and/or intrusion-prevention techniques detect, alert on/prevent, and address covert malware communication channels.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  11.5.2: >
    A change-detection mechanism (for example, file integrity monitoring tools) is deployed as follows:
    - To alert personnel to unauthorized modification (including changes, additions, and deletions) of critical files.
    - To perform critical file comparisons at least once weekly.
  11.6: Unauthorized changes on payment pages are detected and responded to.
  11.6.1: >
    A change- and tamper-detection mechanism is deployed as follows:
    - To alert personnel to unauthorized modification (including indicators of compromise, changes, additions, and deletions) to the HTTP headers and the contents of payment pages as received by the consumer browser.
    - The mechanism is configured to evaluate the received HTTP header and payment page.
    - The mechanism functions are performed as follows:
    - At least once every seven days
    OR
    - Periodically (at the frequency defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1).
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12: Support Information Security with Organizational Policies and Programs
  12.1: A comprehensive information security policy that governs and provides direction for protection of the entity's information assets is known and current.
  12.1.1: >
    An overall information security policy is:
    - Established.
    - Published.
    - Maintained.
    - Disseminated to all relevant personnel, as well as to relevant vendors and business partners.
  12.1.2: >
    The information security policy is:
    - Reviewed at least once every 12 months.
    - Updated as needed to reflect changes to business objectives or risks to the environment.
  12.1.3: The security policy clearly defines information security roles and responsibilities for all personnel, and all personnel are aware of and acknowledge their information security responsibilities.
  12.1.4: Responsibility for information security is formally assigned to a Chief Information Security Officer or other information security knowledgeable member of executive management.
  12.2: Acceptable use policies for end-user technologies are defined and implemented.
  12.2.1: >
    Acceptable use policies for end-user technologies are documented and implemented, including:
    - Explicit approval by authorized parties.
    - Acceptable uses of the technology.
    - List of products approved by the company for employee use, including hardware and software.
  12.3: Risks to the cardholder data environment are formally identified, evaluated, and managed.
  12.3.1: >
    Each PCI DSS requirement that provides flexibility for how frequently it is performed (for example, requirements to be performed periodically) is supported by a targeted risk analysis that is documented and includes:
    - Identification of the assets being protected.
    - Identification of the threat(s) that the requirement is protecting against.
    - Identification of factors that contribute to the likelihood and/or impact of a threat being realized.
    - Resulting analysis that determines, and includes justification for, how frequently the requirement must be performed to minimize the likelihood of the threat being realized.
    - Review of each targeted risk analysis at least once every 12 months to determine whether the results are still valid or if an updated risk analysis is needed.
    - Performance of updated risk analyses when needed, as determined by the annual review.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.3.2: >
    A targeted risk analysis is performed for each PCI DSS requirement that the entity meets with the customized approach, to include:
    - Documented evidence detailing each element specified in Appendix D: Customized Approach (including, at a minimum, a controls matrix and risk analysis).
    - Approval of documented evidence by senior management.
    - Performance of the targeted analysis of risk at least once every 12 months.
  12.3.3: >
    Cryptographic cipher suites and protocols in use are documented and reviewed at least once every 12 months, including at least the following:
    - An up-to-date inventory of all cryptographic cipher suites and protocols in use, including purpose and where used.
    - Active monitoring of industry trends regarding continued viability of all cryptographic cipher suites and protocols in use.
    - A documented strategy to respond to anticipated changes in cryptographic vulnerabilities.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.3.4: >
    Hardware and software technologies in use are reviewed at least once every 12 months, including at least the following:
    - Analysis that the technologies continue to receive security fixes from vendors promptly.
    - Analysis that the technologies continue to support (and do not preclude) the entity's PCI DSS compliance.
    - Documentation of any industry announcements or trends related to a technology, such as when a vendor has announced \u201cend of life\u201d plans for a technology.
    - Documentation of a plan, approved by senior management, to remediate outdated technologies, including those for which vendors have announced \u201cend of life\u201d plans.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.4: PCI DSS compliance is managed.
  12.4.1: >
    Additional requirement for service providers only: Responsibility is established by executive management for the protection of cardholder data and a PCI DSS compliance program to include:
    - Overall accountability for maintaining PCI DSS compliance.
    - Defining a charter for a PCI DSS compliance program and communication to executive management.
  12.4.2: >
    Additional requirement for service providers only: Reviews are performed at least once every three months to confirm that personnel are performing their tasks in accordance with all security policies and operational procedures. Reviews are performed by personnel other than those responsible for performing the given task and include, but are not limited to, the following tasks:
    - Daily log reviews.
    - Configuration reviews for network security controls.
    - Applying configuration standards to new systems.
    - Responding to security alerts.
    - Change-management processes.
  12.4.2.1: >
    Additional requirement for service providers only: Reviews conducted in accordance with Requirement 12.4.2 are documented to include:
    - Results of the reviews.
    - Documented remediation actions taken for any tasks that were found to not be performed at Requirement 12.4.2.
    - Review and sign-off of results by personnel assigned responsibility for the PCI DSS compliance program.
  12.5: PCI DSS scope is documented and validated.
  12.5.1: An inventory of system components that are in scope for PCI DSS, including a description of function/use, is maintained and kept current.
  12.5.2: >
    PCI DSS scope is documented and confirmed by the entity at least once every 12 months and upon significant change to the in-scope environment. At a minimum, the scoping validation includes:
    - Identifying all data flows for the various payment stages (for example, authorization, capture settlement, chargebacks, and refunds) and acceptance channels (for example, card-present, card-not-present, and e-commerce).
    - Updating all data-flow diagrams per Requirement 1.2.4.
    - Identifying all locations where account data is stored, processed, and transmitted, including but not limited to: 1) any locations outside of the currently defined CDE, 2) applications that process CHD, 3) transmissions between systems and networks, and 4) file backups.
    - Identifying all system components in the CDE, connected to the CDE, or that could impact security of the CDE.
    - Identifying all segmentation controls in use and the environment(s) from which the CDE is segmented, including justification for environments being out of scope.
    - Identifying all connections from third-party entities with access to the CDE.
    - Confirming that all identified data flows, account data, system components, segmentation controls, and connections from third parties with access to the CDE are included in scope.
  12.5.2.1: >
    Additional requirement for service providers only: PCI DSS scope is documented and confirmed by the entity at least once every six months and upon significant change to the in-scope environment. At a minimum, the scoping validation includes all the elements specified in Requirement 12.5.2.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.5.3: >
    Additional requirement for service providers only: Significant changes to organizational structure result in a documented (internal) review of the impact to PCI DSS scope and applicability of controls, with results communicated to executive management.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.6: Security awareness education is an ongoing activity.
  12.6.1: A formal security awareness program is implemented to make all personnel aware of the entity's information security policy and procedures, and their role in protecting the cardholder data.
  12.6.2: >
    The security awareness program is:
    - Reviewed at least once every 12 months, and
    - Updated as needed to address any new threats and vulnerabilities that may impact the security of the entity's CDE, or the information provided to personnel about their role in protecting cardholder data.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.6.3: >
    Personnel receive security awareness training as follows:
    - Upon hire and at least once every 12 months.
    - Multiple methods of communication are used.
    - Personnel acknowledge at least once every 12 months that they have read and understood the information security policy and procedures.
  12.6.3.1: >
    Security awareness training includes awareness of threats and vulnerabilities that could impact the security of the CDE, including but not limited to:
    - Phishing and related attacks.
    - Social engineering.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.6.3.2: >
    Security awareness training includes awareness about the acceptable use of end-user technologies in accordance with Requirement 12.2.1.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.7: Personnel are screened to reduce risks from insider threats.
  12.7.1: Potential personnel who will have access to the CDE are screened, within the constraints of local laws, prior to hire to minimize the risk of attacks from internal sources.
  12.8: Risk to information assets associated with third-party service provider (TPSP) relationships is managed.
  12.8.1: A list of all third-party service providers (TPSPs) with which account data is shared or that could affect the security of account data is maintained, including a description for each of the services provided.
  12.8.2: >
    Written agreements with TPSPs are maintained as follows:
    - Written agreements are maintained with all TPSPs with which account data is shared or that could affect the security of the CDE.
    - Written agreements include acknowledgments from TPSPs that they are responsible for the security of account data the TPSPs possess or otherwise store, process, or transmit on behalf of the entity, or to the extent that they could impact the security of the entity's CDE.
  12.8.3: An established process is implemented for engaging TPSPs, including proper due diligence prior to engagement.
  12.8.4: A program is implemented to monitor TPSPs' PCI DSS compliance status at least once every 12 months.
  12.8.5: Information is maintained about which PCI DSS requirements are managed by each TPSP, which are managed by the entity, and any that are shared between the TPSP and the entity.
  12.9: Third-party service providers (TPSPs) support their customers' PCI DSS compliance.
  12.9.1: >
    Additional requirement for service providers only: TPSPs acknowledge in writing to customers that they are responsible for the security of account data the TPSP possesses or otherwise stores, processes, or transmits on behalf of the customer, or to the extent that they could impact the security of the customer's CDE.
  12.9.2: >
    Additional requirement for service providers only: TPSPs support their customers' requests for information to meet Requirements 12.8.4 and 12.8.5 by providing the following upon customer request:
    - PCI DSS compliance status information for any service the TPSP performs on behalf of customers (Requirement 12.8.4).
    - Information about which PCI DSS requirements are the responsibility of the TPSP and which are the responsibility of the customer, including any shared responsibilities (Requirement 12.8.5)
  "12.10": Suspected and confirmed security incidents that could impact the CDE are responded to immediately.
  12.10.1: >
    An incident response plan exists and is ready to be activated in the event of a suspected or confirmed security incident. The plan includes, but is not limited to:
    - Roles, responsibilities, and communication and contact strategies in the event of a suspected or confirmed security incident, including notification of payment brands and acquirers, at a minimum.
    - Incident response procedures with specific containment and mitigation activities for different types of incidents.
    - Business recovery and continuity procedures.
    - Data backup processes.
    - Analysis of legal requirements for reporting compromises.
    - Coverage and responses of all critical system components.
    - Reference or inclusion of incident response procedures from the payment brands.
  12.10.2: >
    At least once every 12 months, the security incident response plan is:
    - Reviewed and the content is updated as needed.
    - Tested, including all elements listed in Requirement 12.10.1.
  12.10.3: Specific personnel are designated to be available on a 24/7 basis to respond to suspected or confirmed security incidents.
  12.10.4: Personnel responsible for responding to suspected and confirmed security incidents are appropriately and periodically trained on their incident response responsibilities.
  12.10.4.1: >
    The frequency of periodic training for incident response personnel is defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  12.10.5: >
    The security incident response plan includes monitoring and responding to alerts from security monitoring systems, including but not limited to:
    - Intrusion-detection and intrusion-prevention systems.
    - Network security controls.
    - Change-detection mechanisms for critical files.
    - The change-and tamper-detection mechanism for payment pages. This bullet is a best practice until 31 March 2025, after which it will be required as part of Requirement 12.10.5 and must be fully considered during a PCI DSS assessment.
    - Detection of unauthorized wireless access points.
  12.10.6: The security incident response plan is modified and evolved according to lessons learned and to incorporate industry developments.
  12.10.7: >
    Incident response procedures are in place, to be initiated upon the detection of stored PAN anywhere it is not expected, and include:
    - Determining what to do if PAN is discovered outside the CDE, including its retrieval, secure deletion, and/or migration into the currently defined CDE, as applicable.
    - Identifying whether sensitive authentication data is stored with PAN.
    - Determining where the account data came from and how it ended up where it was not expected.
    - Remediating data leaks or process gaps that resulted in the account data being where it was not expected.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  A1: Additional PCI DSS Requirements for Multi-Tenant Service Providers
  A1.1: Multi-tenant service providers protect and separate all customer environments and data.
  A1.1.1: >
    Logical separation is implemented as follows:
    - The provider cannot access its customers' environments without authorization.
    - Customers cannot access the provider's environment without authorization.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  A1.1.2: Controls are implemented such that each customer only has permission to access its own cardholder data and CDE.
  A1.1.3: Controls are implemented such that each customer can only access resources allocated to them.
  A1.1.4: >
    The effectiveness of logical separation controls used to separate customer environments is confirmed at least once every six months via penetration testing.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  A1.2: Multi-tenant service providers facilitate logging and incident response for all customers.
  A1.2.1: >
    Audit log capability is enabled for each customer's environment that is consistent with PCI DSS Requirement 10, including:
    - Logs are enabled for common third-party applications.
    - Logs are active by default.
    - Logs are available for review only by the owning customer.
    - Log locations are clearly communicated to the owning customer.
    - Log data and availability is consistent with PCI DSS Requirement 10.
  A1.2.2: Processes or mechanisms are implemented to support and/or facilitate prompt forensic investigations in the event of a suspected or confirmed security incident for any customer.
  A1.2.3: >
    Processes or mechanisms are implemented for reporting and addressing suspected or confirmed security incidents and vulnerabilities, including:
    - Customers can securely report security incidents and vulnerabilities to the provider.
    - The provider addresses and remediates suspected or confirmed security incidents and vulnerabilities according to Requirement 6.3.1.
    Note: This requirement is a best practice until 31 March 2025, after which it will be required and must be fully considered during a PCI DSS assessment.
  A2: Additional PCI DSS Requirements for Entities Using SSL/Early TLS for Card-Present POS POI Terminal Connections
  A2.1: POI terminals using SSL and/or early TLS are confirmed as not susceptible to known SSL/TLS exploits.
  A2.1.1: Where POS POI terminals at the merchant or payment acceptance location use SSL and/or early TLS, the entity confirms the devices are not susceptible to any known exploits for those protocols.
  A2.1.2: >
    Additional requirement for service providers only: All service providers with existing connection points to POS POI terminals that use SSL and/or early TLS as defined in A2.1 have a formal Risk Mitigation and Migration Plan in place that includes:
    - Description of usage, including what data is being transmitted, types and number of systems that use and/or support SSL/early TLS, and type of environment.
    - Risk-assessment results and risk-reduction controls in place.
    - Description of processes to monitor for new vulnerabilities associated with SSL/early TLS.
    - Description of change control processes that are implemented to ensure SSL/early TLS is not implemented into new environments.
    - Overview of migration project plan to replace SSL/early TLS at a future date.
  A2.1.3: >
    Additional requirement for service providers only: All service providers provide a secure service offering.
  A3: Designated Entities Supplemental Validation (DESV)

"""
