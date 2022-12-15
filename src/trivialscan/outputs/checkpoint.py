import logging
import pickle
from io import BufferedReader, BytesIO
from pathlib import Path
from os import path
from hashlib import sha1

DEFAULT_CACHE_PATH = "/tmp"
logger = logging.getLogger(__name__)


def unfinished(name: bytes, cache_dir: str = DEFAULT_CACHE_PATH):
    Path(cache_dir).mkdir(exist_ok=True)
    checkpoint_file = Path(path.join(cache_dir, f"{sha1(name).hexdigest()}.pkl"))
    return checkpoint_file.is_file()


def resume(name: bytes, cache_dir: str = DEFAULT_CACHE_PATH):
    Path(cache_dir).mkdir(exist_ok=True)
    checkpoint_file = Path(path.join(cache_dir, f"{sha1(name).hexdigest()}.pkl"))
    if not checkpoint_file.is_file():
        return None
    logger.info(f"Resuming checkpoint {name.decode()}")
    return pickle.load(BufferedReader(BytesIO(checkpoint_file.read_bytes())))


def mark(name: bytes, data, cache_dir: str = DEFAULT_CACHE_PATH) -> int:
    logger.info(f"Setting checkpoint {name.decode()}")
    Path(cache_dir).mkdir(exist_ok=True)
    checkpoint_file = Path(path.join(cache_dir, f"{sha1(name).hexdigest()}.pkl"))
    try:
        pkl = pickle.dumps(data)
    except TypeError:
        return
    return checkpoint_file.write_bytes(pkl)


def clear(name: bytes, cache_dir: str = DEFAULT_CACHE_PATH):
    Path(cache_dir).mkdir(exist_ok=True)
    checkpoint_file = Path(path.join(cache_dir, f"{sha1(name).hexdigest()}.pkl"))
    if not checkpoint_file.is_file():
        return
    logger.info(f"Clearing checkpoint {name.decode()}")
    checkpoint_file.unlink()
