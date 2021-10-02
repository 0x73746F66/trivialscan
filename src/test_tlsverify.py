import pytest
import tlsverify
from pprint import pprint

class TestValidator:
    _verify :tlsverify.Validator
    _metadata :dict
    host = 'google.com'
    def _setup(self):
        if not hasattr(self, '_verify'):
            self._verify = tlsverify.Validator(self.host)
            self._metadata = self._verify.get_metadata()

    def test_tlsverify_no_args(self):
        with pytest.raises(TypeError):
            tlsverify.Validator()

    def test_tlsverify_not_a_domain(self):
        with pytest.raises(ValueError):
            tlsverify.Validator('not a domain')

    def test_tlsverify_not_a_port(self):
        with pytest.raises(TypeError):
            tlsverify.Validator(self.host, '443')

    def test_tlsverify_cafiles(self):
        with pytest.raises(TypeError):
            tlsverify.Validator('badssl.com', 443, cafiles='/path/to/cafile')

    def test_tlsverify_metadata(self):
        self._setup()
        assert isinstance(self._metadata, dict)
        assert 'host' in self._metadata

    def test_tlsverify_metadata_host(self):
        self._setup()
        assert hasattr(self._verify.metadata, 'host')
        assert self.host == self._metadata.get('host')
        assert self.host == self._verify.metadata.host

    def test_tlsverify_metadata_port(self):
        self._setup()
        assert 443 == self._metadata.get('port')
        assert 443 == self._verify.metadata.port

    def test_tlsverify_valid(self):
        self._setup()
        self._verify.verify()
        assert self._verify.certificate_valid is True
        assert len(self._verify.certificate_verify_messages) == 0

    def test_tlsverify_valid_chain(self):
        self._setup()
        self._verify.verify()
        assert self._verify.certificate_chain_valid is True
        assert self._verify.certificate_chain_validation_result is None
        pprint(self._metadata)
