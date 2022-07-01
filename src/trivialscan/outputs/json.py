import json
from pathlib import Path
from . import parse_filename, track_delta


def save_to(
    template_filename: str,
    data,
    track_changes: bool = False,
    tracking_template_filename: str = None,
) -> str:
    previous_report = None
    if track_changes and tracking_template_filename:
        tracking_file = Path(parse_filename(tracking_template_filename))
        track_changes = tracking_file.is_file()

    if track_changes:
        try:
            previous_report = json.loads(tracking_file.read_text(encoding="utf8"))
        except json.decoder.JSONDecodeError:
            pass

    filename = parse_filename(template_filename)
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
    return json_path.absolute().as_posix()
