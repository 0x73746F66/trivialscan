
import sys
import logging
import validators
from datetime import datetime
from dataclasses import asdict
from OpenSSL.crypto import X509
from . import exceptions, util
from .transport import Transport
from .validator import Validator, LeafCertValidator, RootCertValidator, PeerCertValidator


__version__ = 'tls-verify==1.1.5'
__module__ = 'tlsverify'

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"
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

    validator = LeafCertValidator(use_sqlite=False)
    transport = Transport(host, port)
    if client_pem is not None:
        transport.pre_client_authentication_check(client_pem_path=client_pem)

    if not transport.connect_least_secure(cafiles=cafiles, use_sni=use_sni) or not isinstance(transport.server_certificate, X509):
        raise exceptions.ValidationError(exceptions.VALIDATION_ERROR_TLS_FAILED.format(host=host, port=port))
    validator.tmp_path_prefix = tmp_path_prefix
    validator.mount(transport)
    validator.verify()
    validator.verify_chain()
    validator.pcidss_compliant()
    validator.fips_compliant()
    validator.nist_compliant()
    results = validator.peer_validations
    results.append(validator)
    valid = all(v.certificate_valid for v in results)
    return valid, results

def normalise(result :Validator, certificate_type :str) -> dict:
    data = asdict(result.metadata)
    data['certificate_valid'] = result.certificate_valid
    if isinstance(result, LeafCertValidator):
        data['certificate_chain_valid'] = result.certificate_chain_valid
        data['certificate_chain_validation_result'] = result.certificate_chain_validation_result
    data['certificate_type'] = certificate_type
    data['expiry_status'] = util.date_diff(result.certificate.not_valid_after)
    data['verification_results'] = {}
    data['compliance_results'] = {}
    for key, value in result.validation_checks.items():
        data['verification_results'][key] = value
    for key, value in result.compliance_checks.items():
        data['compliance_results'][key] = value
    data['verification_details'] = result.certificate_verify_messages

    return data

def to_dict(results :list[Validator], evaluation_duration_seconds :int) -> dict:
    data = {
        'generator': __version__,
        'date': datetime.utcnow().replace(microsecond=0).isoformat(),
        'evaluation_duration_seconds': evaluation_duration_seconds,
        'validations': []
    }
    for result in results:
        if isinstance(result, RootCertValidator):
            data['validations'].append(normalise(result, 'Root CA'))
        if isinstance(result, PeerCertValidator):
            cert_type = 'Intermediate Certificate'
            if result.metadata.certificate_intermediate_ca:
                cert_type = 'Intermediate CA'
            data['validations'].append(normalise(result, cert_type))
        if isinstance(result, LeafCertValidator):
            data['validations'].append(normalise(result, 'Leaf Certificate'))
    return data
