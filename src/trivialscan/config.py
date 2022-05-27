import logging
from os.path import expanduser
from pathlib import Path
import yaml

__module__ = "trivialscan.config"

logger = logging.getLogger(__name__)


def _merge_evaluations(evaluations: list, default_evaluations: list) -> list:
    default_evaluations.extend(
        list(
            map(
                lambda x, y: y if x.get("key") != y.get("key") else x.update(y),
                default_evaluations,
                evaluations,
            )
        )
    )
    return list(filter(None, default_evaluations))


def _combine(default_values: dict, user_conf: dict, custom_conf: dict) -> dict:
    ret_config = {
        "defaults": {
            **default_values.get("defaults", {}),
            **user_conf.get("defaults", {}),
            **custom_conf.get("defaults", {}),
        }
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
    evaluations = _merge_evaluations(
        user_conf.get("evaluations", []), default_values["evaluations"]
    )
    ret_config["evaluations"] = _merge_evaluations(
        custom_conf.get("evaluations", []), evaluations
    )
    return ret_config


def get_config(filename: str = ".trivialscan-config.yaml") -> dict:
    rel_config = {}
    user_config = {}
    rel_config_path = Path(filename)
    user_config_path = Path(f"{expanduser('~')}/{filename}")
    default_values = yaml.safe_load(DEFAULT_VALUES)
    if rel_config_path.is_file():
        rel_config = yaml.safe_load(rel_config_path.read_text(encoding="utf8"))
    if user_config_path.is_file():
        user_config = yaml.safe_load(user_config_path.read_text(encoding="utf8"))

    return _combine(default_values, user_config, rel_config)


DEFAULT_VALUES = b"""
---
defaults:
  use_sni: True
  cafiles:
  client_pem:
  tmp_path_prefix: /tmp

outputs:
  - type: console

evaluations:
  - key: client_renegotiation
    group: tls_negotiation
    label_as: Client initiated TLS renegotiation
    issue: Server accepts client-initiated insecure renegotiation, numerous exploits exists and many have been assigned CVE
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
        display_as: Misconfigured
        score: -40

  - key: dnssec
    group: dns_configuration
    label_as: DNSSEC
    issue: DNS by itself is not secure, without DNSSEC ICANN states any attacker can easily redirect a user to any malicious actor controlled server without the user or authentic server realising it.
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
    issue: DSA keys, and RSA keys smaller than 1024 bits offer no security and should not be used at all, whether they are known to be compromised or not. The pwnedkeys database keeps records of compromised 1024 bit and larger RSA/DSA keys, as well as elliptic-curve keys on the P-256, P-384, and P-521 curves. If your private key is ever compromised, it should be considered an emergency, and your priority should be resolving the issue immediately. If an unauthorized person gains access to your private key, they can assume the identity that your certificate is intended to protect (e.g. you, your company, and/or your website).
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

  - key: deprecated_protocol_negotiated
    group: tls_negotiation
    label_as: Deprecated TLS protocol negotiated
    issue: TBA
    references:
      - name:
        url:
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
    label_as: Known weak ciphers negotiated
    issue: TBA
    metadata:
      - key: negotiated_cipher
        format_str: " %s"
      - key: negotiated_cipher_bits
        format_str: " (%d bits)"
    references:
      - name:
        url:
    anotate_results:
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Good Configuration
        score: 120
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Misconfigured
        score: -200

  - key: known_weak_cipher_offered
    group: tls_negotiation
    label_as: Known weak ciphers offered
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
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
        evaluation_value: "[yellow]WARN![/yellow]"
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

  - key: revocation_crlite
    group: certificate
    label_as: Intermediate Certificate Revocation (crlite)
    issue: Certificate Revocation only occurs if the Certificate is no longer intended to be used for it's designed purpose, and offers no security at best, or represents a known compormise.
    cvss2: AV:L/AC:H/Au:N/C:P/I:N/A:N
    cvss3: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
    cve:
    references:
      - name: Security Advisory
        url: https://blog.mozilla.org/security/tag/crlite/
    anotate_results:
      - value: True
        evaluation_value: "[light_coral]FAIL![/light_coral]"
        display_as: Compromised
        score: -200
      - value: False
        evaluation_value: "[dark_sea_green2]PASS![/dark_sea_green2]"
        display_as: Not Revoked
        score: 50
"""
config = get_config()
