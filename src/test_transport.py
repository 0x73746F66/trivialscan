from trivialscan.transport import Transport
from trivialscan import constants

HOST = "google.com"

TRANSPORT = Transport(HOST)


def test_setup():
    assert TRANSPORT.connect_least_secure() is True


def test_host():
    assert TRANSPORT.host == HOST


def test_port():
    assert 443 == TRANSPORT.port


def test_negotiated_cipher():
    assert isinstance(TRANSPORT.negotiated_cipher, str)


def test_negotiated_protocol():
    assert TRANSPORT.negotiated_protocol in [
        constants.TLS1_0_LABEL,
        constants.TLS1_1_LABEL,
        constants.TLS1_2_LABEL,
    ]


def test_sni_support():
    assert isinstance(TRANSPORT.sni_support, bool)
