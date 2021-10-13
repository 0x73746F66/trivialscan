from tlsverify.validator import Validator
from tlsverify.transport import Transport

class TestValidator:
    _verify :Validator
    host = 'http2.github.io'
    def _setup(self):
        if not hasattr(self, '_verify'):
            transport = Transport(self.host)
            transport.connect_least_secure()
            self._verify = Validator()
            self._verify.mount(transport)

    def test_tlsverify_no_args(self):
        v = Validator()
        assert v.certificate_valid is False
        assert v.validation_checks == {}
        assert v.certificate_verify_messages == []
        assert v.certificate_chain_valid is None
        assert v.certificate_chain_validation_result is None
        assert v._pem is None
        assert v._der is None
        assert v.x509 is None
        assert v.certificate is None
        assert v._pem_certificate_chain == []
        assert v.certificate_chain == []


    def test_tlsverify_verify(self):
        self._setup()
        self._verify.verify()
        assert self._verify.certificate_valid is True
        assert len(self._verify.certificate_verify_messages) == 0

    def test_tlsverify_valid_chain(self):
        want = 'Validated: digital_signature,key_encipherment,server_auth'
        self._setup()
        self._verify.verify_chain()
        assert self._verify.certificate_chain_valid is True
        assert self._verify.certificate_chain_validation_result == want
