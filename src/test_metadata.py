from datetime import datetime
import pytest
import tlsverify
from pprint import pprint

class TestMetadata:
    _verify :tlsverify.Validator
    host = 'ssllabs.com'
    def setup(self):
        if not hasattr(self, '_verify'):
            self._verify = tlsverify.Validator(self.host)
        self._verify.extract_metadata()

    def test_metadata(self):
        self.setup()
        assert isinstance(self._verify.metadata, tlsverify.util.Metadata)
    def test_host(self):
        self.setup()
        assert self._verify.metadata.host == self.host
    def test_port(self):
        self.setup()
        assert 443 == self._verify.metadata.port
    def test_certificate_public_key_type(self):
        self.setup()
        assert self._verify.metadata.certificate_public_key_type in ['RSA', 'DSA', 'EC', 'DH']
    def test_certificate_key_size(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_key_size, int)
    def test_certificate_serial_number(self):
        self.setup()
        assert len(self._verify.metadata.certificate_serial_number.replace(':', '')) == 64
    def test_certificate_serial_number_decimal(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_serial_number_decimal, int)
    def test_certificate_serial_number_hex(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_serial_number_hex, str)
    def test_certificate_subject(self):
        self.setup()
        assert self.host in self._verify.metadata.certificate_subject
    def test_certificate_issuer(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_issuer, str)
    def test_certificate_issuer_country(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_issuer_country, str)
    def test_certificate_signature_algorithm(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_signature_algorithm, str)
    def test_certificate_pin_sha256(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_pin_sha256, str)
    def test_certificate_sha256_fingerprint(self):
        self.setup()
        assert len(self._verify.metadata.certificate_sha256_fingerprint) == 64
    def test_certificate_sha1_fingerprint(self):
        self.setup()
        assert len(self._verify.metadata.certificate_sha1_fingerprint) == 40
    def test_certificate_md5_fingerprint(self):
        self.setup()
        assert len(self._verify.metadata.certificate_md5_fingerprint) == 32
    def test_certificate_not_before(self):
        self.setup()
        assert datetime.fromisoformat(self._verify.metadata.certificate_not_before)
    def test_certificate_not_after(self):
        self.setup()
        assert datetime.fromisoformat(self._verify.metadata.certificate_not_after)
    def test_certificate_common_name(self):
        self.setup()
        assert self.host in self._verify.metadata.certificate_common_name
    def test_certificate_san(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_san, list)
    def test_certificate_subject_key_identifier(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_subject_key_identifier, str)
    def test_certificate_authority_key_identifier(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_authority_key_identifier, str)
    def test_certificate_extensions(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_extensions, list)
    def test_certificate_is_self_signed(self):
        self.setup()
        assert isinstance(self._verify.metadata.certificate_is_self_signed, bool)
    def test_negotiated_cipher(self):
        self.setup()
        assert isinstance(self._verify.metadata.negotiated_cipher, str)
    def test_negotiated_protocol(self):
        self.setup()
        assert self._verify.metadata.negotiated_protocol in ['TLSv1', 'TLSv1.1', 'TLSv1.2']
    def test_sni_support(self):
        self.setup()
        assert isinstance(self._verify.metadata.sni_support, bool)
    def test_revocation_ocsp_stapling(self):
        self.setup()
        assert isinstance(self._verify.metadata.revocation_ocsp_stapling, bool)
    def test_revocation_ocsp_must_staple(self):
        self.setup()
        assert isinstance(self._verify.metadata.revocation_ocsp_must_staple, bool)
