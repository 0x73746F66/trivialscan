from pathlib import Path
import pytest
from OpenSSL import SSL
from tlsverify import verify
from tlsverify.validator import CertValidator, PeerCertValidator
from tlsverify.transport import Transport
from tlsverify import exceptions

class TestValidator:
    _verify :CertValidator
    host = 'http2.github.io'
    def _setup(self):
        if not hasattr(self, '_verify'):
            transport = Transport(self.host)
            transport.connect_least_secure()
            self._verify = CertValidator()
            self._verify.mount(transport)

    def test_tranport_mount(self):
        self._setup()
        assert isinstance(self._verify.transport, Transport)

    def test_cert_validator_no_args(self):
        v = CertValidator()
        assert v.certificate_valid is False
        assert v.validation_checks == {}
        assert v.certificate_verify_messages == []
        assert v.certificate_chain_valid is None
        assert v.certificate_chain_validation_result is None
        assert v.transport is None
        assert v.metadata is None
        assert v._pem is None
        assert v._der is None
        assert v.x509 is None
        assert v.certificate is None
        assert v._pem_certificate_chain == []
        assert v.certificate_chain == []
        assert v.peer_validations == []

    def test_peer_cert_validator_no_args(self):
        v = PeerCertValidator()
        assert v.certificate_valid is False
        assert v.validation_checks == {}
        assert v.certificate_verify_messages == []
        assert v.metadata is None
        assert v._pem is None
        assert v._der is None
        assert v.x509 is None
        assert v.certificate is None
 
    def test_tlsverify_valid_chain(self):
        want = 'Validated: digital_signature,key_encipherment,server_auth'
        self._setup()
        self._verify.verify_chain()
        assert self._verify.certificate_chain_valid is True
        assert self._verify.certificate_chain_validation_result == want

    def test_no_host(self):
        with pytest.raises(ValueError):
            verify(host=None)

    def test_no_port(self):
        with pytest.raises(TypeError):
            verify(self.host, port='80')

    def test_bad_cafiles(self):
        with pytest.raises(TypeError):
            verify(self.host, cafiles='/bad.pem')

    def test_no_sni(self):
        with pytest.raises(TypeError):
            verify(self.host, use_sni=None)

    def test_client_pem(self):
        pem = '/tmp/client.pem'
        p = Path(pem)
        p.touch()
        with pytest.raises(SSL.Error):
            verify(self.host, client_pem=pem)

    def test_bad_client_pem(self):
        with pytest.raises(TypeError):
            verify(self.host, client_pem=True)

    def test_bad_tmp_path_prefix(self):
        with pytest.raises(TypeError):
            verify(self.host, tmp_path_prefix=True)

    def test_no_connection(self):
        with pytest.raises(exceptions.ValidationError):
            verify(host='not-a-real.site')

    def test_tlsverify_verify(self):
        is_valid, results = verify(self.host)
        assert is_valid
        assert len(results) > 1

    def test_with_tmp_path_prefix(self):
        is_valid, results = verify(self.host, tmp_path_prefix='/tmp')
        assert is_valid
        assert len(results) > 1
