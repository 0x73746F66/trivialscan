from datetime import datetime
from tlsverify.metadata import Metadata
from tlsverify.transport import Transport
from tlsverify.validator import CertValidator

class TestMetadata:
    _verify :CertValidator
    host = 'http2.github.io'
    def setup(self):
        if not hasattr(self, '_transport'):
            self._transport = Transport(self.host)
            self._transport.connect_least_secure()
            self._verify = CertValidator()
            self._verify.mount(self._transport)

    def test_metadata(self):
        self.setup()
        assert isinstance(self._verify.metadata, Metadata)
        assert self._verify.metadata.host == self.host
        assert 443 == self._verify.metadata.port
        assert self._verify.metadata.certificate_public_key_type in ['RSA', 'DSA', 'EC', 'DH']
        assert isinstance(self._verify.metadata.certificate_public_key_size, int)
        assert len(self._verify.metadata.certificate_serial_number.replace(':', '')) == 64
        assert isinstance(self._verify.metadata.certificate_serial_number_decimal, int)
        assert isinstance(self._verify.metadata.certificate_serial_number_hex, str)
        assert isinstance(self._verify.metadata.certificate_issuer, str)
        assert isinstance(self._verify.metadata.certificate_issuer_country, str)
        assert isinstance(self._verify.metadata.certificate_signature_algorithm, str)
        assert isinstance(self._verify.metadata.certificate_pin_sha256, str)
        assert len(self._verify.metadata.certificate_sha256_fingerprint) == 64
        assert len(self._verify.metadata.certificate_sha1_fingerprint) == 40
        assert len(self._verify.metadata.certificate_md5_fingerprint) == 32
        assert datetime.fromisoformat(self._verify.metadata.certificate_not_before)
        assert datetime.fromisoformat(self._verify.metadata.certificate_not_after)
        assert isinstance(self._verify.metadata.certificate_san, list)
        assert isinstance(self._verify.metadata.certificate_subject_key_identifier, str)
        assert isinstance(self._verify.metadata.certificate_authority_key_identifier, str)
        assert isinstance(self._verify.metadata.certificate_extensions, list)
        assert isinstance(self._verify.metadata.certificate_is_self_signed, bool)
        assert isinstance(self._verify.metadata.negotiated_cipher, str)
        assert self._verify.metadata.negotiated_protocol in ['TLSv1', 'TLSv1.1', 'TLSv1.2']
        assert isinstance(self._verify.metadata.sni_support, bool)
        assert isinstance(self._verify.metadata.revocation_ocsp_stapling, bool)
        assert isinstance(self._verify.metadata.revocation_ocsp_must_staple, bool)
