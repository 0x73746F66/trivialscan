from trivialscan.transport import Transport
from trivialscan import constants

HOST = "http2.github.io"


class TestMetadata:
    _transport = Transport(HOST)

    def setup(self):
        if not hasattr(self, "_transport"):
            self._transport.connect_least_secure()

    def test_host(self):
        self.setup()
        assert self._transport.host == HOST

    def test_port(self):
        self.setup()
        assert 443 == self._transport.port

    def test_negotiated_cipher(self):
        self.setup()
        assert isinstance(self._transport.negotiated_cipher, str)

    def test_negotiated_protocol(self):
        self.setup()
        assert self._transport.negotiated_protocol in [
            constants.TLS1_0_LABEL,
            constants.TLS1_1_LABEL,
            constants.TLS1_2_LABEL,
        ]

    def test_sni_support(self):
        self.setup()
        assert isinstance(self._transport.sni_support, bool)
