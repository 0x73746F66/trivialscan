# https://github.com/devsecur/robot-attack/blob/master/robot-detect.py
# target: mail.idsno.net
import logging
import math
import socket
import os
from typing import Union

from ...util import timeout
from ...transport import TLSTransport
from ...certificate import LeafCertificate
from .. import BaseEvaluationTask

# This uses all TLS_RSA ciphers with AES and 3DES
ch = bytearray.fromhex(
    "16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203"  # pragma: allowlist secret
)
ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex(
    "005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0"  # pragma: allowlist secret
)
TIMEOUT = 3
RND_PMS = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"  # pragma: allowlist secret
MSG_FASTOPEN = 0x20000000
# set to true if you want to generate a signature or if the first ciphertext is not PKCS#1 v1.5 conform
EXECUTE_BLINDING = True

# We only enable TCP fast open if the Linux proc interface exists
ENABLE_FASTOPEN = os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")

logger = logging.getLogger(__name__)


def powmod(x, y, z):
    "Bruce Schneier's powmod"
    number = 1
    while y:
        if y & 1:
            number = (number * x) % z
        y >>= 1
        x = (x * x) % z
    return number


class EvaluationTask(BaseEvaluationTask):
    probe_info: str = "Active network scan"

    def __init__(self, transport: TLSTransport, metadata: dict, config: dict) -> None:
        super().__init__(transport, metadata, config)
        self._leaf: LeafCertificate = None
        self._cke_version = None
        self._cke_2and_prefix = None

    @timeout(10)
    def evaluate(self) -> Union[bool, None]:
        for cert in self.transport.store.tls_state.certificates:
            if isinstance(cert, LeafCertificate):
                self._leaf = cert
                break
        if self._leaf is None:
            self.substitution_metadata["tls_robot"] = "missing Leaf Cedrtificate"
            return None
        if self._leaf.public_key_type not in ["RSA", "DSA"]:
            self.substitution_metadata[
                "tls_robot"
            ] = f"{self._leaf.public_key_type} not subject to TLS ROBOT attacks"
            return False
        if self._leaf.public_key_modulus is None:
            logger.info("tls_robot: No public key modulus available")
            self.substitution_metadata["tls_robot"] = "No public key modulus available"
            return None
        N = self._leaf.public_key_modulus
        e = self._leaf.public_key_exponent
        modulus_bits = int(math.ceil(math.log(N, 2)))
        modulus_bytes = (modulus_bits + 7) // 8
        self._cke_2and_prefix = bytearray.fromhex(
            "{0:0{1}x}".format(modulus_bytes + 6, 4)
            + "10"
            + "{0:0{1}x}".format(modulus_bytes + 2, 6)
            + "{0:0{1}x}".format(modulus_bytes, 4)
        )
        # pad_len is length in hex chars, so bytelen * 2
        pad_len = (modulus_bytes - 48 - 3) * 2
        rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]

        pms_good_in = int("0002" + rnd_pad + "00" + "0303" + RND_PMS, 16)
        # wrong first two bytes
        pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + RND_PMS, 16)
        # 0x00 on a wrong position, also trigger older JSSE bug
        pms_bad_in2 = int("0002" + rnd_pad + "11" + RND_PMS + "0011", 16)
        # no 0x00 in the middle
        pms_bad_in3 = int("0002" + rnd_pad + "11" + "1111" + RND_PMS, 16)
        # wrong version number (according to Klima / Pokorny / Rosa paper)
        pms_bad_in4 = int("0002" + rnd_pad + "00" + "0202" + RND_PMS, 16)

        pms_good = int(powmod(pms_good_in, e, N)).to_bytes(
            modulus_bytes, byteorder="big"
        )
        pms_bad1 = int(powmod(pms_bad_in1, e, N)).to_bytes(
            modulus_bytes, byteorder="big"
        )
        pms_bad2 = int(powmod(pms_bad_in2, e, N)).to_bytes(
            modulus_bytes, byteorder="big"
        )
        pms_bad3 = int(powmod(pms_bad_in3, e, N)).to_bytes(
            modulus_bytes, byteorder="big"
        )
        pms_bad4 = int(powmod(pms_bad_in4, e, N)).to_bytes(
            modulus_bytes, byteorder="big"
        )

        oracle_good = self._oracle(pms_good, messageflow=False)
        oracle_bad1 = self._oracle(pms_bad1, messageflow=False)
        oracle_bad2 = self._oracle(pms_bad2, messageflow=False)
        oracle_bad3 = self._oracle(pms_bad3, messageflow=False)
        oracle_bad4 = self._oracle(pms_bad4, messageflow=False)

        if oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4:
            logger.info(
                f"Identical results ({oracle_good}), retrying with changed messageflow"
            )
            oracle_good = self._oracle(pms_good, messageflow=True)
            oracle_bad1 = self._oracle(pms_bad1, messageflow=True)
            oracle_bad2 = self._oracle(pms_bad2, messageflow=True)
            oracle_bad3 = self._oracle(pms_bad3, messageflow=True)
            oracle_bad4 = self._oracle(pms_bad4, messageflow=True)
            if oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4:
                self.substitution_metadata[
                    "tls_robot"
                ] = f"Identical results ({oracle_good}), no working oracle found"
                return False
            else:
                flow = True
        else:
            flow = False

        # Re-checking all oracles to avoid unreliable results
        oracle_good_verify = self._oracle(pms_good, messageflow=flow)
        oracle_bad_verify1 = self._oracle(pms_bad1, messageflow=flow)
        oracle_bad_verify2 = self._oracle(pms_bad2, messageflow=flow)
        oracle_bad_verify3 = self._oracle(pms_bad3, messageflow=flow)
        oracle_bad_verify4 = self._oracle(pms_bad4, messageflow=flow)

        if (
            oracle_good != oracle_good_verify
            or oracle_bad1 != oracle_bad_verify1
            or oracle_bad2 != oracle_bad_verify2
            or oracle_bad3 != oracle_bad_verify3
            or oracle_bad4 != oracle_bad_verify4
        ):
            self.substitution_metadata[
                "tls_robot"
            ] = "aborted with inconsistent results"
            return None
        # If the response to the invalid PKCS#1 request (oracle_bad1) is equal to both
        # requests starting with 0002, we have a weak oracle. This is because the only
        # case where we can distinguish valid from invalid requests is when we send
        # correctly formatted PKCS#1 message with 0x00 on a correct position. This
        # makes our oracle weak
        if oracle_bad1 == oracle_bad2 == oracle_bad3:
            self.substitution_metadata[
                "tls_robot"
            ] = "The oracle is weak, the attack could take too long"
        else:
            self.substitution_metadata[
                "tls_robot"
            ] = "The oracle is strong, real attack is possible"

        return True

    def _oracle(self, pms, messageflow=False):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if not ENABLE_FASTOPEN:
                s.connect(
                    (
                        self.transport.store.tls_state.peer_address,
                        self.transport.store.tls_state.port,
                    )
                )
                s.sendall(ch)
            else:
                s.sendto(
                    ch,
                    MSG_FASTOPEN,
                    (
                        self.transport.store.tls_state.peer_address,
                        self.transport.store.tls_state.port,
                    ),
                )
            s.settimeout(TIMEOUT)
            buf = bytearray.fromhex("")
            i = 0
            bend = 0
            while True:
                # we try to read twice
                while i + 5 > bend:
                    buf += s.recv(4096)
                    bend = len(buf)
                # this is the record size
                psize = buf[i + 3] * 256 + buf[i + 4]
                # if the size is 2, we received an alert
                if psize == 2:
                    return "The server sends an Alert after ClientHello"
                # try to read further record data
                while i + psize + 5 > bend:
                    buf += s.recv(4096)
                    bend = len(buf)
                # check whether we have already received a ClientHelloDone
                if (buf[i + 5] == 0x0E) or (buf[bend - 4] == 0x0E):
                    break
                i += psize + 5
            self._cke_version = buf[9:11]
            s.send(bytearray(b"\x16") + self._cke_version)
            s.send(self._cke_2and_prefix)
            s.send(pms)
            if not messageflow:
                s.send(bytearray(b"\x14") + self._cke_version + ccs)
                s.send(bytearray(b"\x16") + self._cke_version + enc)
            try:
                alert = s.recv(4096)
                if len(alert) == 0:
                    return "No data received from server"
                if alert[0] == 0x15:
                    if len(alert) < 7:
                        return f"TLS alert was truncated ({repr(alert)})"
                    return f"TLS alert {alert[6]} of length {len(alert)}"
                else:
                    return f"Received something other than an alert ({alert[0:10]})"
            except ConnectionResetError as ex:
                logger.exception(ex)
                return "ConnectionResetError"
            except socket.timeout:
                return "Timeout waiting for alert"
            finally:
                s.close()
        except Exception as ex:
            logger.exception(ex)
            return str(ex)
