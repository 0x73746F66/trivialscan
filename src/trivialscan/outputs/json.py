import json
from datetime import datetime
from pathlib import Path
from . import parse_filename, track_delta
from ..certificate import BaseCertificate
from ..transport import TLSTransport


def save_to(
    template_filename: str,
    data,
    track_changes: bool = False,
    tracking_template_filename: str = None,
    **kwargs
) -> str:
    previous_report = None
    if track_changes and tracking_template_filename:
        tracking_file = Path(parse_filename(tracking_template_filename, **kwargs))
        track_changes = tracking_file.is_file()

    if track_changes:
        try:
            previous_report = json.loads(tracking_file.read_text(encoding="utf8"))
        except json.decoder.JSONDecodeError:
            pass

    filename = parse_filename(template_filename, **kwargs)
    json_path = Path(filename)
    if track_changes and previous_report:
        data["queries"] = track_delta(
            previous_report.get("queries", []), data["queries"]
        )
    Path(json_path.parent).mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(
            data,
            sort_keys=True,
            indent=4,
            default=str,
        ),
        encoding="utf8",
    )

    return json_path.as_posix()


def save_partial(config, when: str, data_type: str, data, **kwargs) -> list[str]:
    files = []
    json_output = [
        n["path"]
        for n in config.get("outputs", [])
        if n.get("type") == "json" and n.get("when") == when
    ]
    if json_output:
        for json_file in json_output:
            files.append(
                save_to(
                    template_filename=json_file,
                    data={
                        "generator": "trivialscan",
                        "account_name": kwargs.get("account_name"),
                        "client_name": kwargs.get("client_name"),
                        "project_name": kwargs.get("project_name"),
                        "date": datetime.utcnow().replace(microsecond=0).isoformat(),
                        data_type: data,
                    },
                    **kwargs
                )
            )
    return files


def parse_host_filename(
    transport: TLSTransport,
    template_filename: str,
) -> str:
    return parse_filename(
        template_filename,
        hostname=transport.store.tls_state.hostname,
        port=transport.store.tls_state.port,
        peer_address=transport.store.tls_state.peer_address,
        negotiated_protocol=transport.store.tls_state.negotiated_protocol,
        negotiated_cipher=transport.store.tls_state.negotiated_cipher,
    )


def parse_cert_filename(
    cert: BaseCertificate,
    template_filename: str,
) -> str:
    return parse_filename(
        template_filename,
        sha1_fingerprint=cert.sha1_fingerprint,
        md5_fingerprint=cert.md5_fingerprint,
        sha256_fingerprint=cert.sha256_fingerprint,
        serial_number_hex=cert.serial_number_hex,
        public_key_type=cert.public_key_type,
        public_key_size=cert.public_key_size,
        subject_key_identifier=cert.subject_key_identifier,
        spki_fingerprint=cert.spki_fingerprint,
        version=cert.version,
        validation_level=cert.validation_level,
        not_before=cert.not_before,
        not_after=cert.not_after,
    )
