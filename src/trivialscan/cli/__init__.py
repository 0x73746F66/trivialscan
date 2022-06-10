from rich.console import Console
from rich.table import Table


def log(message:str, con:None|Console = None, **kwargs):
    if not isinstance(con, Console):
        return
    aside = kwargs.get('aside', '')
    if kwargs.get('hostname'):
        if kwargs.get('port'):
            aside += f"{kwargs.get('hostname')}:{kwargs.get('port')}"
        else:
            aside += kwargs.get('hostname')
    table = Table.grid(expand=True)
    table.add_column()
    table.add_column(justify="right", style="dim", no_wrap=True, overflow=None)
    table.add_row(message, aside)
    con.print(table)
