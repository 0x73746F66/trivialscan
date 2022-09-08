import logging
import configparser
from os import path
from pathlib import Path
from typing import Union

import keyring

from ..config import CONFIG_PATH

__module__ = "trivialscan.cli.credentials"
KEYRING_KEY = "trivialscan-registration-token-{account_name}"
KEYRING_SUPPORT = False
try:
    KEYRING_SUPPORT = isinstance(
        keyring.get_keyring(), keyring.backends.SecretService.Keyring
    )
except AttributeError:
    pass
CREDENTIALS_FILE = path.join(CONFIG_PATH, "credentials")
logger = logging.getLogger(__name__)


def load_credentials() -> Union[dict, None]:
    credentials_path = Path(CREDENTIALS_FILE)
    if not credentials_path.is_file():
        return None
    config = configparser.ConfigParser()
    config.read(CREDENTIALS_FILE)
    return {key: dict(conf) for key, conf in dict(config).items()}


def load_local(account_name: str) -> Union[dict, None]:
    try:
        if KEYRING_SUPPORT:
            registration_token = keyring.get_password(
                "system", KEYRING_KEY.format(account_name=account_name)
            )
            if registration_token:
                return registration_token
    except keyring.errors.InitError:
        logger.warning(
            "Skipping keyring credential store, it is not supported on this system"
        )
    except keyring.errors.KeyringError as ex:
        logger.debug(ex, exc_info=True)

    config = load_credentials()
    return (
        None if not config or account_name not in config else config.get(account_name)
    )


def save_local(account_name: str, client_name: str, token: str) -> bool:
    try:
        if KEYRING_SUPPORT:
            keyring.set_password(
                "system", KEYRING_KEY.format(account_name=account_name), token
            )
            registration_token = keyring.get_password(
                "system", KEYRING_KEY.format(account_name=account_name)
            )
            if registration_token == token:
                return True
    except keyring.errors.InitError:
        logger.warning(
            "Skipping keyring credential store, it is not supported on this system"
        )
    except keyring.errors.KeyringError as ex:
        logger.debug(ex, exc_info=True)

    config = configparser.ConfigParser()
    credentials_path = Path(CREDENTIALS_FILE)
    if credentials_path.is_file():
        config.read(CREDENTIALS_FILE)
    else:
        Path(CONFIG_PATH).mkdir(exist_ok=True)

    config.setdefault(account_name, {})
    config[account_name]["token"] = token
    config[account_name]["client_name"] = client_name
    try:
        with open(CREDENTIALS_FILE, "w", encoding="utf8") as buff:
            config.write(buff)
        return True
    except (FileExistsError, FileNotFoundError, configparser.Error):
        pass
    return False


def get_token(account_name: str) -> Union[str, None]:
    credentials = load_local(account_name)
    return credentials.get("token")
