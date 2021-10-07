__module__ = 'tlsverify.exceptions'

X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18
X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2
X509_V_ERR_UNABLE_TO_GET_CRL = 3
X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4
X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5
X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6
X509_V_ERR_CERT_SIGNATURE_FAILURE = 7
X509_V_ERR_CRL_SIGNATURE_FAILURE = 8
X509_V_ERR_CERT_NOT_YET_VALID = 9
X509_V_ERR_CERT_HAS_EXPIRED = 10
X509_V_ERR_CRL_NOT_YET_VALID = 11
X509_V_ERR_CRL_HAS_EXPIRED = 12
X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13
X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14
X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15
X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16
X509_V_ERR_OUT_OF_MEM = 17
X509_V_ERR_APPLICATION_VERIFICATION = 50
X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19
X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20
X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21
X509_V_ERR_PATH_LENGTH_EXCEEDED = 25
X509_V_ERR_CERT_REVOKED = 23
X509_V_ERR_INVALID_CA = 24
X509_V_ERR_INVALID_PURPOSE = 26
X509_V_ERR_CERT_UNTRUSTED = 27
X509_V_ERR_CERT_REJECTED = 28
X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29
X509_V_ERR_AKID_SKID_MISMATCH = 30
X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31
X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32
X509_MESSAGES = {
    18: "self signed certificate, the passed certificate is self signed and the same certificate cannot be found in the list of trusted certificates",
    2: "unable to get issuer certificate, the issuer certificate of a looked up certificate could not be found. This normally means the list of trusted certificates is not complete.",
    3: "unable to get certificate CRL, the CRL of a certificate could not be found.",
    4: "unable to decrypt certificate's signature, the certificate signature could not be decrypted. This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys.",
    5: "unable to decrypt CRL's signature, the CRL signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused.",
    6: "unable to decode issuer public key, the public key in the certificate SubjectPublicKeyInfo could not be read.",
    7: "certificate signature failure, the signature of the certificate is invalid.",
    8: "CRL signature failure, the signature of the certificate is invalid.",
    9: "certificate is not yet valid, the certificate is not yet valid: the notBefore date is after the current time.",
    10: "certificate has expired, the certificate has expired: that is the notAfter date is before the current time.",
    11: "CRL is not yet valid, the CRL is not yet valid.",
    12: "CRL has expired, the CRL has expired.",
    13: "format error in certificate's notBefore field, the certificate notBefore field contains an invalid time.",
    14: "format error in certificate's notAfter field, the certificate notAfter field contains an invalid time.",
    15: "format error in CRL's lastUpdate field, the CRL lastUpdate field contains an invalid time.",
    16: "format error in CRL's nextUpdate field, the CRL nextUpdate field contains an invalid time.",
    17: "This should never happen.",
    19: "self signed certificate in certificate chain, the certificate chain could be built up using the untrusted certificates but the root could not be found locally.",
    20: "unable to get local issuer certificate, the issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found.",
    21: "unable to verify the first certificate, no signatures could be verified because the chain contains only one certificate and it is not self signed.",
    22: "path length constraint exceeded, the basicConstraints pathlength parameter has been exceeded.",
    23: "certificate revoked, the certificate has been revoked.",
    24: "invalid CA certificate, a CA certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose.",
    25: "path length constraint exceeded, the basicConstraints pathlength parameter has been exceeded.",
    26: "unsupported certificate purpose, the supplied certificate cannot be used for the specified purpose.",
    27: "certificate not trusted, the root CA is not marked as trusted for the specified purpose.",
    28: "certificate rejected, the root CA is marked to reject the specified purpose.",
    29: "subject issuer mismatch, the current candidate issuer certificate was rejected because its subject name did not match the issuer name of the current certificate. Only displayed when the -issuer_checks option is set.",
    30: "authority and subject key identifier mismatch, the current candidate issuer certificate was rejected because its subject key identifier was present and did not match the authority key identifier current certificate. Only displayed when the -issuer_checks option is set.",
    31: "authority and issuer serial number mismatch, the current candidate issuer certificate was rejected because its issuer name and serial number was present and did not match the authority key identifier of the current certificate. Only displayed when the -issuer_checks option is set.",
    32: "key usage does not include certificate signing, the current candidate issuer certificate was rejected because its keyUsage extension does not permit certificate signing.",
    50: "This should never happen.",
}

VALIDATION_ERROR_TLS_FAILED = 'Unable to negotiate a TLS socket connection with server at {host}:{port} to obtain the Certificate'
VALIDATION_ERROR_CLIENT_AUTHENTICATION = 'Client Authentication failed, the provided client certificate did not match any of the server provided subjects'

class ValidationError(ValueError):
    def __init__(self, message :str = None, openssl_errno :int = None):
        if openssl_errno in X509_MESSAGES.keys():
            if message is None:
                message = X509_MESSAGES[openssl_errno]
            if isinstance(message, str):
                message += '\n' + X509_MESSAGES[openssl_errno]
        super().__init__(message)
        self.openssl_errno = openssl_errno
