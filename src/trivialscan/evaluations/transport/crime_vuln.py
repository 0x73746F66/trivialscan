import logging
import random
import string
import zlib
from typing import Union
from Crypto.Cipher import AES, ARC4
from Crypto import Random

from ...util import timeout
from ...exceptions import EvaluationNotRelevant
from ...transport import TLSTransport
from .. import BaseEvaluationTask

IV = Random.new().read(AES.block_size)
CBC_KEY = Random.new().read(AES.block_size)
RC4_KEY = "".join(random.sample(string.ascii_uppercase + string.digits, k=17))

logger = logging.getLogger(__name__)


def pad(s):
    return (16 - len(s) % 16) * chr((16 - len(s) - 1) % 16)


def encrypt_aes(msg):
    data = msg.encode()
    compress = zlib.compress(data)
    padding = pad(compress)
    raw = compress + padding.encode()
    cipher = AES.new(CBC_KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(raw)


def encrypt_arc4(msg):
    data = msg
    cipher = ARC4.new(RC4_KEY)
    return cipher.encrypt(zlib.compress(data))


def decrypt(enc):
    decipher = ARC4.new(RC4_KEY)
    return decipher.decrypt(zlib.decompress(enc))


class EvaluationTask(BaseEvaluationTask):
    """
    Let's be clear about what a CRIME exploit is
    As long as either CBC or RC4 is offered the attack is fairly trivial, but
    getting something useful... There is no shortcuts.
    The malicious CRIME exploit will extract everything you tell it too, and
    being good at regex to parse it all to find anything is the only skill an
    attacker needs.
    Therefore this evaluation does one thing only:
    Try to demonstrate deriving a benign header or cookie value for proof of
    concept only, a real exploit would not be so polite and could extract all
    data to be parsed real simply
    """

    probe_info: str = "Active network scan"

    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)
        self._known = "secret="
        self._secret = f"{self._known}2ac8a4ea7909bccb4c81cefd3f7765d4"

    @timeout(10)
    def evaluate(self) -> Union[bool, None]:
        cbc_results = []
        rc4_results = []
        for offered_cipher in self.transport.store.tls_state.offered_ciphers:
            cbc_results.append("-CBC-" in offered_cipher)
            rc4_results.append("RC4" in offered_cipher)
        if not any(cbc_results + rc4_results):
            raise EvaluationNotRelevant
        if any(cbc_results):
            result = self._crime_cbc()
            if result:
                return True
        if any(rc4_results):
            result = self._crime_rc4()
            if result:
                return True

        return False

    def _crime_cbc(self) -> bool:
        p = self._two_true_recursive([], 0)
        logger.debug(f"Found {p} possibilities of CRIME cbc secret flag")
        self.substitution_metadata["crime_cbc"] = f"Found {p} possibilities"
        return p > 0

    def _crime_rc4(self) -> bool:
        p = self._two_tries_recursive([], 0)
        logger.debug(f"Found {p} possibilities of CRIME rc4 secret flag")
        self.substitution_metadata["crime_rc4"] = f"Found {p} possibilities"
        return p > 0

    def _adjust_padding(self):
        garb = ""
        found = []
        param_k = 0
        origin = encrypt_aes(
            garb + self._known + "".join(found) + "~#:/[|/ç" + " " + self._secret
        )
        while True:
            enc = encrypt_aes(
                garb + self._known + "".join(found) + "~#:/[|/ç" + " " + self._secret
            )
            if len(enc) > len(origin):
                break
            else:
                param_k += 1
                garb = "".join(
                    random.sample(string.ascii_lowercase + string.digits, k=param_k)
                )
        return garb[:-1]

    def _two_true_recursive(self, found, p=0) -> int:
        garb = self._adjust_padding()
        tmp = []
        for i in range(33, 127):
            enc1 = encrypt_aes(
                garb
                + self._known
                + "".join(found)
                + chr(i)
                + "~#:/[|/ç"
                + " "
                + self._secret
            )
            enc2 = encrypt_aes(
                garb
                + self._known
                + "~#:/[|/ç"
                + "".join(found)
                + chr(i)
                + " "
                + self._secret
            )
            if len(enc1) < len(enc2):
                tmp.append(chr(i))
        for i in range(0, len(tmp)):
            t = "temp" + str(i)
            t = list(found)
            t.append(tmp[i])
            logger.debug("\r[+] " + self._known + "%s" % "".join(t))
            p = self._two_true_recursive(t, p)
        if len(tmp) == 0:
            p += 1

        return p

    def _two_tries_recursive(self, found, p=0) -> int:
        tmp = []
        for i in range(33, 127):
            rand1 = "".join(random.sample(string.ascii_lowercase + string.digits, k=17))
            rand2 = "".join(random.sample(string.ascii_lowercase + string.digits, k=17))
            payload = (
                rand1
                + self._known
                + "".join(found)
                + chr(i)
                + "~#:/[|/ç"
                + " "
                + self._secret
                + " "
                + rand2
            )
            enc1 = encrypt_arc4(payload.encode())
            payload = (
                rand1
                + self._known
                + "".join(found)
                + "~#:/[|/ç"
                + chr(i)
                + " "
                + self._secret
                + " "
                + rand2
            )
            enc2 = encrypt_arc4(payload.encode())
            if len(enc1) < len(enc2):
                tmp.append(chr(i))

        for i in range(0, len(tmp)):
            t = "temp" + str(i)
            t = list(found)
            t.append(tmp[i])
            logger.debug("\r[+] " + self._known + "%s" % "".join(t))
            p = self._two_tries_recursive(t, p)
        if len(tmp) == 0:
            p += 1

        return p
