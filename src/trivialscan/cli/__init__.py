from rich.console import Console
from rich.table import Table
from pprint import pprint


CLI_LEVEL_FAIL = "fail"
CLI_LEVEL_WARN = "warn"
CLI_LEVEL_PASS = "pass"  # nosec
CLI_LEVEL_INFO = "info"
CLI_LEVEL_FAIL_DEFAULT = "FAIL!"
CLI_LEVEL_WARN_DEFAULT = "WARN!"
CLI_LEVEL_PASS_DEFAULT = "PASS!"  # nosec
CLI_LEVEL_INFO_DEFAULT = "INFO!"
CLI_COLOR_PRIMARY = "cyan"
CLI_COLOR_FAIL = "light_coral"
CLI_COLOR_WARN = "khaki1"
CLI_COLOR_PASS = "dark_sea_green2"  # nosec
CLI_COLOR_INFO = "deep_sky_blue2"
COLOR_MAP = {
    CLI_LEVEL_FAIL: CLI_COLOR_FAIL,
    CLI_LEVEL_WARN: CLI_COLOR_WARN,
    CLI_LEVEL_PASS: CLI_COLOR_PASS,
    CLI_LEVEL_INFO: CLI_COLOR_INFO,
}
ICON_MAP = {
    CLI_LEVEL_FAIL: ":cross_mark:",
    CLI_LEVEL_WARN: ":bell:",
    CLI_LEVEL_PASS: ":white_heavy_check_mark:",
    CLI_LEVEL_INFO: ":speech_balloon:",
}
DEFAULT_MAP = {
    CLI_LEVEL_FAIL: CLI_LEVEL_FAIL_DEFAULT,
    CLI_LEVEL_WARN: CLI_LEVEL_WARN_DEFAULT,
    CLI_LEVEL_PASS: CLI_LEVEL_PASS_DEFAULT,
    CLI_LEVEL_INFO: CLI_LEVEL_INFO_DEFAULT,
}


def outputln(message: str, con: None | Console = None, **kwargs):
    if not isinstance(con, Console):
        return
    result_level = kwargs.get("result_level", CLI_LEVEL_INFO)
    if not result_level or result_level not in [
        CLI_LEVEL_FAIL,
        CLI_LEVEL_WARN,
        CLI_LEVEL_PASS,
        CLI_LEVEL_INFO,
    ]:
        return
    result_color = COLOR_MAP.get(
        result_level, kwargs.get("result_color", CLI_COLOR_INFO)
    )
    result_text = kwargs.get(
        "result_text", DEFAULT_MAP.get(result_level, CLI_LEVEL_INFO_DEFAULT)
    )
    use_icons = kwargs.get("use_icons", False)
    result_icon = ""
    if use_icons:
        result_icon = kwargs.get("result_icon", ICON_MAP.get(result_level, ""))
    aside = kwargs.get("aside", "")
    if kwargs.get("hostname"):
        if kwargs.get("port"):
            aside += f"{kwargs.get('hostname')}:{kwargs.get('port')}"
        else:
            aside += kwargs.get("hostname")
    open_tag = f"{result_icon.strip()}[{result_color}]"
    close_tag = f"[/{result_color}]"
    bold_result = kwargs.get("bold_result", False)
    if bold_result:
        open_tag = f"{open_tag}[bold]"
        close_tag = f"[/bold]{close_tag}"

    table = Table.grid(expand=True)
    table.add_column()
    table.add_column(justify="right", style="dim", no_wrap=True, overflow=None)
    table.add_row(f"{open_tag}{result_text}{close_tag} {message}", aside)
    con.print(table)


def _outputln(message: str, level: str, con: None | Console = None, **kwargs):
    if "result_level" in kwargs:
        del kwargs["result_level"]
    if "result_color" in kwargs:
        del kwargs["result_color"]
    outputln(message=message, result_level=level, con=con, **kwargs)


def infoln(message: str, con: None | Console = None, **kwargs):
    _outputln(message=message, level=CLI_LEVEL_INFO, con=con, **kwargs)


def failln(message: str, con: None | Console = None, **kwargs):
    _outputln(message=message, level=CLI_LEVEL_FAIL, con=con, **kwargs)


def passln(message: str, con: None | Console = None, **kwargs):
    _outputln(message=message, level=CLI_LEVEL_PASS, con=con, **kwargs)


def warnln(message: str, con: None | Console = None, **kwargs):
    _outputln(message=message, level=CLI_LEVEL_WARN, con=con, **kwargs)
