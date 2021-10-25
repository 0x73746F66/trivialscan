from tlsverify.transport import Transport

class TestMetadata:
    host = 'http2.github.io'
    def setup(self):
        if not hasattr(self, '_transport'):
            self._transport = Transport(self.host)
            self._transport.connect_least_secure()

    def test_host(self):
        self.setup()
        assert self._transport.host == self.host
    def test_port(self):
        self.setup()
        assert 443 == self._transport.port
    def test_negotiated_cipher(self):
        self.setup()
        assert isinstance(self._transport.negotiated_cipher, str)
    def test_negotiated_protocol(self):
        self.setup()
        assert self._transport.negotiated_protocol in ['TLSv1', 'TLSv1.1', 'TLSv1.2']
    def test_sni_support(self):
        self.setup()
        assert isinstance(self._transport.sni_support, bool)
