import platform
import logging
from rich.console import Console
import keyring
from .credentials import CREDENTIALS_FILE, load_local, save_local

__module__ = "trivialscan.cli.register"
KEYRING_SUPPORT = isinstance(
    keyring.get_keyring(), keyring.backends.SecretService.Keyring
)
logger = logging.getLogger(__name__)
console = Console()


def register(args: dict):
    if not args.get("account_name"):
        args["account_name"] = input("Enter an account name (Ctrl+C to exit): ").strip()
    if not args.get("account_name"):
        logger.critical("You must provide an account name")
        return
    if not KEYRING_SUPPORT:
        logger.warning(
            f"keyring is not supported on this system, using: {CREDENTIALS_FILE}"
        )
    credentials = load_local(args["account_name"])
    if args.get("client_name"):
        credentials["client_name"] = args["client_name"]
    if not credentials.get("client_name"):
        credentials["client_name"] = platform.node()
    # TODO call register endpoint
    credentials["token"] = "AAAAAAAAXXXAAAAAAAAA111AAAAA"
    save_local(account_name=args["account_name"], **credentials)
    logger.info(
        {
            **credentials,
            **{
                "operating_system": platform.system(),
                "operating_system_release": platform.release(),
                "operating_system_version": platform.version(),
                "architecture": platform.machine(),
            },
        }
    )
    console.print(
        f"Your client token is: [bold][aquamarine3]{credentials['token']}[/bold][/aquamarine3]"
    )
