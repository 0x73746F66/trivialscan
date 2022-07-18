from rich.console import Console
from rich.table import Table

CLI_FAIL = "fail"
CLI_WARN = "warn"
CLI_PASS = "pass"
CLI_INFO = "info"
CLI_SAVE = "save"
CLI_FAIL_DEFAULT = "FAIL!"
CLI_WARN_DEFAULT = "WARN!"
CLI_PASS_DEFAULT = "PASS!"
CLI_INFO_DEFAULT = "INFO!"
CLI_COLOR_FAIL = "light_coral"
CLI_COLOR_WARN = "khaki1"
CLI_COLOR_PASS = "dark_sea_green2"
CLI_COLOR_INFO = "cyan"
COLOR_MAP = {
    CLI_FAIL: CLI_COLOR_FAIL,
    CLI_WARN: CLI_COLOR_WARN,
    CLI_PASS: CLI_COLOR_PASS,
    CLI_INFO: CLI_COLOR_INFO,
}
ICON_MAP = {
    CLI_FAIL: ":cross_mark:",
    CLI_WARN: ":bell:",
    CLI_PASS: ":white_heavy_check_mark:",
    CLI_INFO: ":speech_balloon:",
    CLI_SAVE: ":floppy_disk:",
}
DEFAULT_MAP = {
    CLI_FAIL: CLI_FAIL_DEFAULT,
    CLI_WARN: CLI_WARN_DEFAULT,
    CLI_PASS: CLI_PASS_DEFAULT,
    CLI_INFO: CLI_INFO_DEFAULT,
    CLI_SAVE: "",
}


def outputln(message: str, con: None | Console = None, **kwargs):
    if not isinstance(con, Console):
        return
    result_level = kwargs.get("result_level", "info")
    if not result_level or result_level not in [CLI_FAIL, CLI_WARN, CLI_PASS, CLI_INFO]:
        return
    result_color = kwargs.get(
        "result_color", COLOR_MAP.get(result_level, CLI_COLOR_INFO)
    )
    result_text = kwargs.get(
        "result_text", DEFAULT_MAP.get(result_level, CLI_INFO_DEFAULT)
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
