import json
import sys
import logging
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import asdict
import validators
from OpenSSL.crypto import X509
from rich import inspect
from rich.console import Console
from rich.style import Style
from rich.logging import RichHandler
from rich.progress import Progress
from rich.table import Table
from rich.style import Style
from rich import box
from . import exceptions, verify, util
from .validator import RootCertValidator, CertValidator, PeerCertValidator, Validator
from .transport import Transport


__version__ = 'tls-verify==0.4.10'
__module__ = 'tlsverify.cli'

CLI_COLOR_OK = 'dark_sea_green2'
CLI_COLOR_NOK = 'light_coral'
CLI_COLOR_ALERT = 'yellow3'
CLI_COLOR_NULL = 'magenta'
CLI_VALUE_TRUSTED = 'Trusted'
CLI_VALUE_NOT_TRUSTED = 'Not Trusted'
CLI_VALUE_VALID = 'Valid'
CLI_VALUE_NOT_VALID = 'Validation Errors'
CLI_VALUE_PASS = 'Pass'
CLI_VALUE_FAIL = 'Fail'
CLI_VALUE_YES = 'Yes'
CLI_VALUE_NO = 'No'
CLI_VALUE_DETECTED = 'Detected'
CLI_VALUE_ABSENT = 'Absent'
CLI_VALUE_OK = 'OK'
CLI_VALUE_NOK = 'NOT OK'
CLI_VALUE_REVOKED = 'Revoked'
CLI_VALUE_NOT_REVOKED = 'Not Revoked'
STYLES = {
    'certificate_valid': {'text': 'Certificate Valid', 'represent_as': (CLI_VALUE_VALID, CLI_VALUE_NOT_VALID), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'certificate_chain_valid': {'text': 'Certificate Chain Valid', 'represent_as': (CLI_VALUE_VALID, CLI_VALUE_NOT_VALID), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'certificate_chain_validation_result': {'text': 'Certificate Chain Validation Result'},
    'not_expired': {'text': 'Certificate is not expired', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'issued_past_tense': {'text': 'Certificate issued in the past', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'common_name_defined': {'text': 'Subject CN was defined', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'common_name_valid': {'text': 'Subject CN has valid syntax', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'match_hostname': {'text': 'Subject CN matches the server host name', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'not_self_signed': {'text': 'Not a self-signed Certificate', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'avoid_known_weak_signature_algorithm': {'text': 'Avoid known weak signature algorithms', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'avoid_known_weak_keys': {'text': 'Avoid known weak public key algorithms', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'avoid_deprecated_protocols': {'text': 'Avoid deprecated TLS protocols', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'avoid_deprecated_dnssec_algorithms': {'text': 'Avoid deprecated DNSSEC algorithms', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'basic_constraints_ca': {'text': 'Avoid enabling impersonation', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'certificate_valid_tls_usage': {'text': 'Key usage appropriate for TLS', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'not_revoked': {'text': 'Certificate chain not revoked', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trusted_ca': {'text': 'Root CA Certificate is trusted', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'valid_dnssec': {'text': 'DNSSEC Valid', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'valid_caa': {'text': 'CAA Valid', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'ocsp_staple_satisfied': {'text': 'OCSP Staple satisfied', 'represent_as': (CLI_VALUE_PASS, CLI_VALUE_FAIL), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'certificate_version': {'text': 'Certificate Version'},
    'certificate_public_key_type': {'text': 'Public Key Type'},
    'certificate_public_key_curve': {'text': 'Public Key Curve', 'null_as': 'N/A', 'null_color': CLI_COLOR_NULL},
    'certificate_public_key_size': {'text': 'Public Key Size'},
    'certificate_public_key_exponent': {'text': 'Public Key Exponent', 'null_as': 'N/A', 'null_color': CLI_COLOR_NULL},
    'certificate_private_key_pem': {'text': 'Derived private key (PEM format)'},
    'certificate_signature_algorithm': {'text': 'Signature Algorithm'},
    'certificate_pin_sha256': {'text': 'Certificate pin (sha256)'},
    'certificate_sha256_fingerprint': {'text': 'Fingerprint (sha256)'},
    'certificate_sha1_fingerprint': {'text': 'Fingerprint (sha1)'},
    'certificate_md5_fingerprint': {'text': 'Fingerprint (md5)'},
    'certificate_serial_number': {'text': 'Serial'},
    'certificate_serial_number_decimal': {'text': 'Serial (decimal)'},
    'certificate_serial_number_hex': {'text': 'Serial (hex)'},
    'certificate_subject': {'text': 'Certificate Subject'},
    'certificate_common_name': {'text': 'Certificate Subject CN'},
    'certificate_issuer': {'text': 'Issuer Subject CN'},
    'certificate_issuer_country': {'text': 'Issuer Country Code'},
    'certificate_not_before': {'text': 'Not Before'},
    'certificate_not_after': {'text': 'Not After'},
    'certificate_subject_key_identifier': {'text': 'Subject Key Identifier (SKI)'},
    'certificate_authority_key_identifier': {'text': 'Authority Key Identifier (AKI)'},
    'certificate_validation_type': {'text': 'Certificate Owner Validation Method'},
    'client_certificate_expected': {'text': 'Client Certificate Expected', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_ALERT, CLI_COLOR_NULL)},
    'certification_authority_authorization': {'text': 'CAA', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'revocation_ocsp_status': {'text': 'Revocation: OCSP'},
    'revocation_ocsp_response': {'text': 'Revocation: OCSP Response'},
    'revocation_ocsp_stapling': {'text': 'Revocation: OCSP Stapling', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'revocation_ocsp_must_staple': {'text': 'Revocation: OCSP Must Staple flag', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'revocation_ocsp_reason': {'text': 'Revocation: OCSP Revoked', 'null_as': CLI_VALUE_NOT_REVOKED, 'null_color': CLI_COLOR_OK, 'color': CLI_COLOR_NOK},
    'revocation_ocsp_time': {'text': 'Revocation: OCSP Revoked time', 'null_as': CLI_VALUE_NOT_REVOKED, 'null_color': CLI_COLOR_OK, 'color': CLI_COLOR_NOK},
    'revocation_crlite': {'text': 'Revocation: Mozilla CRLite', 'represent_as': (CLI_VALUE_REVOKED, CLI_VALUE_NOT_REVOKED), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'sni_support': {'text': 'Server Name Indicator (SNI)', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'negotiated_protocol': {'text': 'Negotiated Protocol'},
    'preferred_protocol': {'text': 'Server Preferred Protocol'},
    'offered_tls_versions': {'text': 'Offered TLS versions'},
    'negotiated_cipher': {'text': 'Negotiated Cipher'},
    'tls_version_intolerance': {'text': 'TLS version intolerance', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'tls_version_intolerance_versions': {'text': 'TLS version intolerance versions'},
    'tls_version_interference': {'text': 'TLS version interference', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'tls_version_interference_versions': {'text': 'TLS version interference versions'},
    'weak_cipher': {'text': 'Negotiated cipher is weak', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'strong_cipher': {'text': 'Negotiated cipher no known weaknesses', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_NOK), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'forward_anonymity': {'text': 'Forward Anonymity (FPS)', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'session_resumption_caching': {'text': 'Session Resumption (caching)', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'session_resumption_tickets': {'text': 'Session Resumption (tickets)', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'session_resumption_ticket_hint': {'text': 'Session Resumption (ticket hint)', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'client_renegotiation': {'text': 'Insecure Client Renegotiation', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'compression_support': {'text': 'TLS Compression', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'dnssec': {'text': 'DNSSEC', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'dnssec_algorithm': {'text': 'DNSSEC Algorithm', 'null_as': 'N/A', 'null_color': CLI_COLOR_NULL},
    'scsv': {'text': 'TLS downgrade prevention (SCSV)', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_expect_ct_report_uri': {'text': 'Expect-CT report-uri', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_hsts': {'text': 'HSTS', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_xfo': {'text': 'X-Frame-Options (XFO)', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_csp': {'text': 'Content Security Policy (CSP)', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_coep': {'text': 'Cross-Origin-Embedder-Policy (COEP)', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_coop': {'text': 'Cross-Origin-Opener-Policy (COOP)', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_corp': {'text': 'Cross-Origin-Resource-Policy (CORP)', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_nosniff': {'text': 'X-Content-Type-Options nosniff', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_unsafe_referrer': {'text': 'Referrer-Policy unsafe-url', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'http_xss_protection': {'text': 'X-XSS-Protection', 'represent_as': (CLI_VALUE_OK, CLI_VALUE_ABSENT), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'http_status_code': {'text': 'HTTP response status code'},
    'http1_support': {'text': 'HTTP/1', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'http1_1_support': {'text': 'HTTP/1.1', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_ALERT, CLI_COLOR_OK)},
    'http2_support': {'text': 'HTTP/2', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_ALERT, CLI_COLOR_OK)},
    'http2_cleartext_support': {'text': 'HTTP/2 Cleartext', 'represent_as': (CLI_VALUE_YES, CLI_VALUE_NO), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'possible_phish_or_malicious': {'text': 'Indicators of Phishing or Malware', 'represent_as': (CLI_VALUE_DETECTED, CLI_VALUE_OK), 'colors': (CLI_COLOR_NOK, CLI_COLOR_OK)},
    'trust_android': {'text': 'Android', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_android_status': {'text': ''},
    'trust_linux': {'text': 'Linux', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_linux_status': {'text': ''},
    'trust_java': {'text': 'Java', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_java_status': {'text': ''},
    'trust_certifi': {'text': 'Python', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_certifi_status': {'text': ''},
    'trust_ccadb': {'text': 'Common CA Database (CCADB)', 'represent_as': (CLI_VALUE_TRUSTED, CLI_VALUE_NOT_TRUSTED), 'colors': (CLI_COLOR_OK, CLI_COLOR_NOK)},
    'trust_ccadb_status': {'text': ''},
}
NEVER_SHOW = [
    'host',
    'port',
    "peer_address",
    "offered_ciphers",
    "certificate_san",
    "certificate_extensions",
    "certificate_is_self_signed",
    "certificate_private_key_pem",
    "subjectKeyIdentifier",
    "authorityKeyIdentifier",
    "certificate_expired",
]
JSON_ONLY = [
    "certificate_expired",
    "certificate_extensions",
    "certificate_private_key_pem",
    "certificate_is_self_signed",
]
SERVER_JSON_ONLY = JSON_ONLY + [
    'host',
    'port',
    "peer_address",
    "offered_ciphers",
]
SERVER_KEYS = [
    'certificate_validation_type',
    'certificate_is_self_signed',
    'certificate_subject',
    'certificate_issuer',
    'certificate_common_name',
    'certificate_intermediate_ca',
    'certificate_root_ca',
    'subjectKeyIdentifier',
    'authorityKeyIdentifier',
    'revocation_ocsp_status',
    'revocation_ocsp_response',
    'revocation_ocsp_reason',
    'revocation_ocsp_time',
    'revocation_ocsp_stapling',
    'revocation_ocsp_must_staple',
    'client_certificate_expected',
    'certification_authority_authorization',
    'dnssec',
    'dnssec_algorithm',
    'scsv',
    'compression_support',
    'tls_version_intolerance',
    'tls_version_intolerance_versions',
    'http_expect_ct_report_uri',
    'http_xss_protection',
    'http_status_code',
    'http1_support',
    'http1_1_support',
    'http2_support',
    'http2_cleartext_support',
    'sni_support',
    'negotiated_protocol',
    'preferred_protocol',
    'offered_tls_versions',
    'tls_version_interference',
    'tls_version_interference_versions',
    'peer_address',
    'negotiated_cipher',
    'weak_cipher',
    'strong_cipher',
    'forward_anonymity',
    'session_resumption_caching',
    'session_resumption_tickets',
    'session_resumption_ticket_hint',
    'client_renegotiation',
    'http_hsts',
    'http_xfo',
    'http_csp',
    'http_coep',
    'http_coop',
    'http_corp',
    'http_nosniff',
    'http_unsafe_referrer',
]
TRUST_KEYS = [
    'trust_ccadb',
    'trust_ccadb_status',
    'trust_java',
    'trust_java_status',
    'trust_android',
    'trust_android_status',
    'trust_linux',
    'trust_linux_status',
    'trust_certifi',
    'trust_certifi_status'
]
ROOT_SKIP = NEVER_SHOW + SERVER_KEYS + [
    'certificate_authority_key_identifier',
    'revocation_crlite',
    'common_name_defined',
    'possible_phish_or_malicious'
]
PEER_SKIP = NEVER_SHOW + SERVER_KEYS + TRUST_KEYS
SERVER_SKIP = NEVER_SHOW + TRUST_KEYS + [
    "certificate_root_ca",
    "certificate_intermediate_ca",
]
FINGERPRINTS = [
    'certificate_sha256_fingerprint',
    'certificate_sha1_fingerprint',
    'certificate_md5_fingerprint',
    'certificate_subject_key_identifier',
    'certificate_authority_key_identifier'
]
JSON_FILE = None

def _make_table(validator :Validator, title :str, caption :str) -> Table:
    title_style = Style(bold=True, color=CLI_COLOR_OK if validator.certificate_valid else CLI_COLOR_NOK)
    table = Table(title=title, caption=caption, title_style=title_style, box=box.SIMPLE)
    table.add_column("", justify="right", style="dark_turquoise", no_wrap=True)
    table.add_column("Result", justify="left", no_wrap=False)
    return table

def _table_data(validator :Validator, table :Table, skip :list[str]) -> Table:
    for i, err in enumerate(validator.certificate_verify_messages):
        table.add_row(f'Note {i+1}', err)
    for key in validator.validation_checks.keys():
        table.add_row(STYLES.get(key,{}).get('text', key), util.styled_boolean(validator.validation_checks[key], STYLES[key]['represent_as'], STYLES[key]['colors']))
    for key in list(vars(validator.metadata).keys()):
        if key in skip:
            continue
        val = getattr(validator.metadata, key)
        if key in FINGERPRINTS and isinstance(val, str):
            table.add_row(STYLES.get(key,{}).get('text', key), util.str_n_split(val).upper())
            continue
        if val is None or (isinstance(val, str) and len(val) == 0):
            table.add_row(STYLES.get(key,{}).get('text', key), util.styled_value(STYLES[key].get('null_as', 'Unknown'), color=STYLES[key].get('null_color', CLI_COLOR_NULL)))
            continue
        if isinstance(val, str) and len(val) > 0:
            table.add_row(STYLES.get(key,{}).get('text', key), util.styled_value(val, color=STYLES[key].get('color')))
            continue
        if isinstance(val, bool):
            table.add_row(STYLES.get(key,{}).get('text', key), util.styled_boolean(val, represent_as=STYLES[key]['represent_as'], colors=STYLES[key]['colors']))
            continue
        table.add_row(STYLES.get(key,{}).get('text', key), util.styled_any(val))
    return table

def _table_ext(validator :Validator, table :Table, skip :list[str]) -> Table:
    for v in validator.metadata.certificate_extensions:
        ext_data = v.copy()
        ext = ext_data['name']
        del ext_data['name']
        if ext in skip:
            continue
        if ext in ext_data:
            ext_sub = ext_data[ext]
            del ext_data[ext]
            table.add_row(f'Extension {ext}', util.styled_dict(ext_data))
            if isinstance(ext_sub, list):
                for sub in ext_sub:
                    if isinstance(sub, str):
                        table.add_row('', util.styled_value(sub))
                        continue
                    if isinstance(sub, dict):
                        for subk, subv in sub.items():
                            if subv is None:
                                table.add_row('', util.styled_value(subk))
                            else:
                                table.add_row('', subk+'='+util.styled_any(subv))
                        continue
                    table.add_row('', util.styled_any(sub))
                continue
            table.add_row('', str(ext_sub))
            continue    
        table.add_row(f'Extention {ext}', util.styled_any(ext_data))
    return table

def peer_outputs(validator :PeerCertValidator) -> Table:
    peer_type = 'Intermediate Certificate'
    if validator.metadata.certificate_intermediate_ca:
        peer_type = 'Intermediate CA'
    title = f'{peer_type}: {validator.metadata.certificate_subject}'
    caption = '\n'.join([
        f'Issuer: {validator.metadata.certificate_issuer}',
        util.date_diff(validator.certificate.not_valid_after),
    ])
    table = _make_table(validator, title, caption)
    table.add_row(STYLES['certificate_valid']['text'], util.styled_boolean(validator.certificate_valid, STYLES['certificate_valid']['represent_as'], STYLES['certificate_valid']['colors']))
    _table_data(validator, table, PEER_SKIP)
    _table_ext(validator, table, PEER_SKIP)
    return table

def root_outputs(validator :RootCertValidator) -> Table:
    title = f'Root CA: {validator.metadata.certificate_subject}'
    caption = util.date_diff(validator.certificate.not_valid_after)
    table = _make_table(validator, title, caption)
    table.add_row(STYLES['certificate_valid']['text'], util.styled_boolean(validator.certificate_valid, ('Trusted', 'Not Trusted'), STYLES['certificate_valid']['colors']))
    _table_data(validator, table, ROOT_SKIP)
    _table_ext(validator, table, ROOT_SKIP)
    return table

def server_outputs(validator :CertValidator) -> Table:
    title = f'{validator.metadata.host}:{validator.metadata.port} ({validator.metadata.peer_address})'
    caption = '\n'.join([
        f'Issuer: {validator.metadata.certificate_issuer}',
        util.date_diff(validator.certificate.not_valid_after),
    ])
    table = _make_table(validator, title, caption)
    table.add_row(STYLES['certificate_valid']['text'], util.styled_boolean(validator.certificate_valid, STYLES['certificate_valid']['represent_as'], STYLES['certificate_valid']['colors']))
    table.add_row(STYLES['certificate_chain_valid']['text'], util.styled_boolean(validator.certificate_chain_valid, STYLES['certificate_chain_valid']['represent_as'], STYLES['certificate_chain_valid']['colors']))
    table.add_row(STYLES['certificate_chain_validation_result']['text'], util.styled_any(validator.certificate_chain_validation_result))
    _table_data(validator, table, SERVER_SKIP)
    _table_ext(validator, table, SERVER_SKIP)
    return table

def update_bar(progress, task):
    def progress_bar(completed :int = None):
        if isinstance(completed, int):
            progress.update(task, completed=completed)
        else:
            progress.update(task, advance=1)
    return progress_bar

def output(result, debug :bool = False):
    console = Console()
    if debug and hasattr(result, 'transport'):
        inspect(result.transport, title=result.transport.negotiated_protocol)
    if debug and hasattr(result, 'metadata'):
        inspect(result.metadata, title=result.metadata.certificate_subject)
    if isinstance(result, RootCertValidator):
        console.print(root_outputs(result))
    if isinstance(result, PeerCertValidator):
        console.print(peer_outputs(result))
    if isinstance(result, CertValidator):
        console.print(server_outputs(result))
    console.print('\n\n')

def validator_data(validator :Validator, certificate_type :str, skip_keys :list) -> dict:
    data = asdict(validator.metadata)
    data['certificate_valid'] = validator.certificate_valid
    if isinstance(validator, CertValidator):
        data['certificate_chain_valid'] = validator.certificate_chain_valid
        data['certificate_chain_validation_result'] = validator.certificate_chain_validation_result
    data['certificate_type'] = certificate_type
    data['expiry_status'] = util.date_diff(validator.certificate.not_valid_after)
    data['verification_details'] = validator.certificate_verify_messages
    data['verification_results'] = validator.validation_checks
    for key in list(vars(validator.metadata).keys()):
        if key in skip_keys and key in data:
            del data[key]
    for v in validator.metadata.certificate_extensions:
        if v.get('name') in skip_keys:
            data['certificate_extensions'][:] = [d for d in data['certificate_extensions'] if d.get('name') != v['name']]

    return data

def make_json(results :list[Validator]) -> str:
    data = []
    for result in results:
        if isinstance(result, RootCertValidator):
            data.append(validator_data(result, 'Root CA', [x for x in ROOT_SKIP if x not in JSON_ONLY]))
        if isinstance(result, PeerCertValidator):
            cert_type = 'Intermediate Certificate'
            if result.metadata.certificate_intermediate_ca:
                cert_type = 'Intermediate CA'
            data.append(validator_data(result, cert_type, [x for x in PEER_SKIP if x not in JSON_ONLY]))
        if isinstance(result, CertValidator):
            data.append(validator_data(result, 'Server Certificate', [x for x in SERVER_SKIP if x not in SERVER_JSON_ONLY]))
    return json.dumps(data, sort_keys=True, default=str)

def main(domains :list[tuple[str, int]], cafiles :list = None, use_sni :bool = True, client_pem :str = None, tmp_path_prefix :str = '/tmp', debug :bool = False) -> list[Validator]:
    if not isinstance(client_pem, str) and client_pem is not None:
        raise TypeError(f"provided an invalid type {type(client_pem)} for client_pem, expected list")
    if not isinstance(cafiles, list) and cafiles is not None:
        raise TypeError(f"provided an invalid type {type(cafiles)} for cafiles, expected list")
    if not isinstance(use_sni, bool):
        raise TypeError(f"provided an invalid type {type(use_sni)} for tlsext, expected list")
    if not isinstance(tmp_path_prefix, str):
        raise TypeError(f"provided an invalid type {type(tmp_path_prefix)} for tmp_path_prefix, expected str")

    evaluation_start = datetime.utcnow()
    results = []
    with Progress() as progress:
        prog_client_auth = progress.add_task("[cyan]Client Authentication...", total=5*len(domains))
        prog_tls = progress.add_task("[cyan]Evaluating TLS...", total=13*len(domains))
        prog_cert_val = progress.add_task("[cyan]Certificate Chain Validation...", total=7*len(domains))
        while not progress.finished:
            for host, port in domains:
                if not isinstance(port, int):
                    raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
                if validators.domain(host) is not True:
                    raise ValueError(f"provided an invalid domain {host}")
                validator = CertValidator()
                transport = Transport(host, port)
                if client_pem is None:
                    progress.update(prog_client_auth, visible=False)
                else:
                    progress.update(prog_client_auth, advance=1)
                    transport.pre_client_authentication_check(client_pem_path=client_pem, progress_bar=update_bar(progress, prog_client_auth))
                    progress.update(prog_client_auth, advance=1)
                if not transport.connect_least_secure(cafiles=cafiles, use_sni=use_sni, progress_bar=update_bar(progress, prog_tls)) or not isinstance(transport.server_certificate, X509):
                    raise exceptions.ValidationError(exceptions.VALIDATION_ERROR_TLS_FAILED.format(host=host, port=port))
                progress.update(prog_tls, advance=1)
                if isinstance(tmp_path_prefix, str):
                    validator.tmp_path_prefix = tmp_path_prefix
                validator.mount(transport)
                progress.update(prog_cert_val, advance=1)
                validator.verify()
                progress.update(prog_cert_val, advance=1)
                validator.verify_chain(progress_bar=update_bar(progress, prog_cert_val))
                results += validator.peer_validations
                results.append(validator)
            progress.update(prog_client_auth, completed=5*len(domains))
            progress.update(prog_tls, completed=13*len(domains))
            progress.update(prog_cert_val, completed=7*len(domains))

    console = Console()
    valid = all(v.certificate_valid for v in results)
    for result in results:
        output(result, debug=debug)
    result_style = Style(color='dark_sea_green2' if valid else 'light_coral')
    console.print('Valid ✓✓✓' if valid else '\nNot Valid. There where validation errors', style=result_style)
    console.print(f'Evaluation duration seconds {(datetime.utcnow() - evaluation_start).total_seconds()}\n\n')
    return results

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="*", help='All unnamed arguments are hosts (and ports) targets to test. ~$ tlsverify google.com:443 github.io owasp.org:80')
    parser.add_argument('-H', '--host', help='single host to check', dest='host', default=None)
    parser.add_argument('-p', '--port', help='TLS port of host', dest='port', default=443)
    parser.add_argument('-c', '--cafiles', help='path to PEM encoded CA bundle file, url or file path accepted', dest='cafiles', default=None)
    parser.add_argument('-C', '--client-pem', help='path to PEM encoded client certificate, url or file path accepted', dest='client_pem', default=None)
    parser.add_argument('-t', '--tmp-path-prefix', help='local file path to use as a prefix when saving temporary files such as those being fetched for client authorization', dest='tmp_path_prefix', default='/tmp')
    parser.add_argument('--disable-sni', help='Do not negotiate SNI using INDA encoded host', dest='disable_sni', action="store_true")
    parser.add_argument('--show-private-key', help='If the private key is exposed, show it in the results', dest='show_private_key', action="store_true")
    parser.add_argument('-j', '--json-file', help='Store to file as JSON', dest='json_file', default=None)
    parser.add_argument('-b', '--progress-bars', help='Show task progress bars', dest='show_progress', action="store_true")
    parser.add_argument('-v', '--errors-only', help='set logging level to ERROR (default CRITICAL)', dest='log_level_error', action="store_true")
    parser.add_argument('-vv', '--warning', help='set logging level to WARNING (default CRITICAL)', dest='log_level_warning', action="store_true")
    parser.add_argument('-vvv', '--info', help='set logging level to INFO (default CRITICAL)', dest='log_level_info', action="store_true")
    parser.add_argument('-vvvv', '--debug', help='set logging level to DEBUG (default CRITICAL)', dest='log_level_debug', action="store_true")
    parser.add_argument('--version', dest='show_version', action="store_true")
    args = parser.parse_args()
    JSON_FILE = args.json_file
    log_level = logging.CRITICAL
    if args.log_level_error:
        log_level = logging.ERROR
    if args.log_level_warning:
        log_level = logging.WARNING
    if args.log_level_info:
        log_level = logging.INFO
    if args.log_level_debug:
        log_level = logging.DEBUG
    handlers = []
    log_format = '%(asctime)s - %(name)s - [%(levelname)s] %(message)s'
    if sys.stdout.isatty():
        log_format = '%(message)s'
        handlers.append(RichHandler(rich_tracebacks=True))
    logging.basicConfig(
        format=log_format,
        level=log_level,
        handlers=handlers
    )
    debug = log_level==logging.DEBUG
    def version(): import platform; print(f"{__version__} Python {sys.version} {platform.platform()} {platform.uname().node} {platform.uname().release} {platform.version()}")
    if args.show_version:
        version()
        sys.exit(0)
    if args.host is None and len(args.targets) == 0:
        version()
        parser.print_help(sys.stderr)
        sys.exit(1)
    if args.host is not None:
        args.targets.append(f'{args.host}:{args.port}')

    domains = []
    for target in args.targets:
        pieces = target.split(':')
        host, port = None, None
        if len(pieces) == 2:
            host, port = pieces
        if len(pieces) == 1:
            host = pieces[0]
            port = args.port
        if validators.domain(host) is not True:
            raise AttributeError(f'host {host} is invalid')
        domains.append((host, int(port)))

    if args.show_private_key:
        SERVER_SKIP.remove('certificate_private_key_pem')
        PEER_SKIP.remove('certificate_private_key_pem')
        ROOT_SKIP.remove('certificate_private_key_pem')

    all_results = []
    if args.show_progress:
        all_results = main( # clones tlsverify.verify and only adds progress bars
            domains=domains,
            cafiles=args.cafiles,
            use_sni=not args.disable_sni,
            client_pem=args.client_pem,
            tmp_path_prefix=args.tmp_path_prefix,
            debug=debug
        )
    else:
        for domain, port in domains:
            evaluation_start = datetime.utcnow()
            _, results = verify(
                domain,
                int(port),
                cafiles=args.cafiles,
                use_sni=not args.disable_sni,
                client_pem=args.client_pem,
                tmp_path_prefix=args.tmp_path_prefix,
            )
            all_results += results
        console = Console()
        valid = all([v.certificate_valid for v in all_results])
        for result in all_results:
            output(result, debug=debug)
        result_style = Style(color=CLI_COLOR_OK if valid else CLI_COLOR_NOK)
        console.print('Valid ✓✓✓' if valid else '\nNot Valid. There where validation errors', style=result_style)
        console.print(f'Evaluation duration seconds {(datetime.utcnow() - evaluation_start).total_seconds()}\n\n')

    if JSON_FILE:
        json_path = Path(JSON_FILE)
        if json_path.is_file():
            json_path.unlink()
        json_path.write_text(make_json(all_results))
