from datetime import datetime
import pytest
import tlsverify
from pprint import pprint

class TestValidator:
    _verify :tlsverify.Validator
    host = 'ssllabs.com'
    def _setup(self):
        if not hasattr(self, '_verify'):
            self._verify = tlsverify.Validator(self.host)
        self._verify.extract_metadata()

    def test_tlsverify_no_args(self):
        v = tlsverify.Validator()
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
        assert v.metadata is None

    def test_tlsverify_not_a_domain(self):
        with pytest.raises(ValueError):
            tlsverify.Validator('not a domain')

    def test_tlsverify_not_a_port(self):
        with pytest.raises(TypeError):
            tlsverify.Validator(self.host, '443')

    def test_tlsverify_cafiles(self):
        with pytest.raises(TypeError):
            tlsverify.Validator('badssl.com', 443, cafiles='/path/to/cafile')

    def test_tlsverify_verify(self):
        self._setup()
        self._verify.verify()
        assert self._verify.certificate_valid is True
        assert len(self._verify.certificate_verify_messages) == 0

    def test_tlsverify_valid_chain(self):
        want = 'Validated: digital_signature,key_encipherment,server_auth'
        self._setup()
        _, x509_certificate_chain, _, _ = tlsverify.util.get_certificates(self.host)
        self._verify.verify_chain(self._verify.convert_x509_to_PEM(x509_certificate_chain))
        assert self._verify.certificate_chain_valid is True
        assert self._verify.certificate_chain_validation_result == want
