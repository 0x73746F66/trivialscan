from typing import Union

from rich.console import Console
from rich.table import Table

from .. import constants


def outputln(message: str, con: Union[Console, None] = None, **kwargs):
    if not isinstance(con, Console):
        return
    result_level = kwargs.get("result_level", constants.RESULT_LEVEL_INFO)
    if not result_level or result_level not in [
        constants.RESULT_LEVEL_FAIL,
        constants.RESULT_LEVEL_WARN,
        constants.RESULT_LEVEL_PASS,
        constants.RESULT_LEVEL_INFO,
    ]:
        return
    result_color = constants.CLI_COLOR_MAP.get(
        result_level, kwargs.get("result_color", constants.CLI_COLOR_INFO)
    )
    result_text = kwargs.get(
        "result_text",
        constants.DEFAULT_MAP.get(result_level, constants.RESULT_LEVEL_INFO_DEFAULT),
    )
    result_label = kwargs.get("result_label", "")

    use_icons = kwargs.get("use_icons", False)
    result_icon = ""
    if use_icons:
        result_icon = kwargs.get(
            "result_icon", constants.CLI_ICON_MAP.get(result_level, "")
        )
    aside = kwargs.get("aside", "")
    if kwargs.get("hostname"):
        if kwargs.get("port"):
            aside += f"{kwargs.get('hostname')}:{kwargs.get('port')}"
        else:
            aside += kwargs.get("hostname")
    open_tag = f"{result_icon.strip()} [{result_color}]".strip()
    close_tag = f"[/{result_color}]"
    bold_result = kwargs.get("bold_result", False)
    if bold_result:
        open_tag = f"{open_tag}[bold]"
        close_tag = f"[/bold]{close_tag}"

    table = Table.grid(expand=True)
    table.add_column()
    table.add_column(justify="right", style="dim", no_wrap=True, overflow=None)
    table.add_row(
        f"{open_tag}{result_text} {message}{close_tag}", f"{result_label} {aside}"
    )
    con.print(table)


def _outputln(message: str, level: str, con: Union[Console, None] = None, **kwargs):
    if "result_level" in kwargs:
        del kwargs["result_level"]
    if "result_color" in kwargs:
        del kwargs["result_color"]
    outputln(message=message, result_level=level, con=con, **kwargs)


def infoln(message: str, con: Union[Console, None] = None, **kwargs):
    _outputln(message=message, level=constants.RESULT_LEVEL_INFO, con=con, **kwargs)


def failln(message: str, con: Union[Console, None] = None, **kwargs):
    _outputln(message=message, level=constants.RESULT_LEVEL_FAIL, con=con, **kwargs)


def passln(message: str, con: Union[Console, None] = None, **kwargs):
    _outputln(message=message, level=constants.RESULT_LEVEL_PASS, con=con, **kwargs)


def warnln(message: str, con: Union[Console, None] = None, **kwargs):
    _outputln(message=message, level=constants.RESULT_LEVEL_WARN, con=con, **kwargs)
