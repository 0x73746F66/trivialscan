import logging
import validators
from OpenSSL.crypto import X509
from . import exceptions
from .transport import Transport
from .validator import Validator, CertValidator


__module__ = 'tlsverify'
logger = logging.getLogger(__name__)

# When chaning this ensure cli.main() is also updated
def verify(host :str, port :int = 443, cafiles :list = None, use_sni :bool = True, client_pem :str = None, tmp_path_prefix :str = '/tmp') -> tuple[bool,list[Validator]]:
    if not isinstance(port, int):
        raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    if not isinstance(client_pem, str) and client_pem is not None:
        raise TypeError(f"provided an invalid type {type(client_pem)} for client_pem, expected list")
    if not isinstance(cafiles, list) and cafiles is not None:
        raise TypeError(f"provided an invalid type {type(cafiles)} for cafiles, expected list")
    if not isinstance(use_sni, bool):
        raise TypeError(f"provided an invalid type {type(use_sni)} for tlsext, expected list")
    if not isinstance(tmp_path_prefix, str):
        raise TypeError(f"provided an invalid type {type(tmp_path_prefix)} for tmp_path_prefix, expected str")

    validator = CertValidator()
    transport = Transport(host, port)
    if client_pem is not None:
        transport.pre_client_authentication_check(client_pem_path=client_pem)
    if not transport.connect_least_secure(cafiles=cafiles, use_sni=use_sni) or not isinstance(transport.server_certificate, X509):
        raise exceptions.ValidationError(exceptions.VALIDATION_ERROR_TLS_FAILED.format(host=host, port=port))
    if isinstance(tmp_path_prefix, str):
        validator.tmp_path_prefix = tmp_path_prefix
    validator.mount(transport)
    validator.verify()
    validator.verify_chain()    
    results = validator.peer_validations
    results.append(validator)
    valid = all([v.certificate_valid for v in results])
    return valid, results
