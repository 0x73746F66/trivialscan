__module__ = "trivialscan.exceptions"

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

VALIDATION_ERROR_TLS_FAILED = "Unable to negotiate a TLS socket connection with server at {host}:{port} to obtain the Certificate"
VALIDATION_ERROR_CLIENT_AUTHENTICATION = "Client Authentication failed, the provided client certificate did not match any of the server provided subjects"
VALIDATION_ERROR_SCSV = "Server preferred protocol {protocol} was avoided and {fallback} was negotiated instead, consider Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks (rfc7507)"
VALIDATION_ERROR_CERTIFICATION_AUTHORITY_AUTHORIZATION = "This domain is not enabled for CAA verification (rfc8659), CAA DNS records were not provided"
VALIDATION_ERROR_CERTIFICATE_VALIDATION_TYPE = "DV Certificates are favored by attackers and seeing one used raises skepticism. DV Certificates are issued for ease-of-use and not for security purposes, and there are known trivial DNS take-over attacks enabled by DV Certificates. An OV or EV Certificate is the distinct opposite of a DV Certificate, attackers avoid using them, they are issued for security purposes specifically as an effective mitigation to the known DNS take-over attacks."
VALIDATION_ERROR_DNSSEC_REGISTERED_DOMAIN = "DNSSEC (rfc6840) provided DS and DNSKEY records, but validation failed for the target subdomain and registered domain name"
VALIDATION_ERROR_DNSSEC_TARGET = "DNSSEC (rfc6840) provided DS and DNSKEY records, but validation failed for the target subdomain and only the registered domain name could be validated"
VALIDATION_ERROR_DNSSEC_MISSING = "This domain is not enabled for DNSSEC (rfc6840), DS and DNSKEY records were not provided"
VALIDATION_ERROR_SESSION_RESUMPTION_CACHING = "Session Resumption (caching) This server has confidentiality vulnerability and a tracking issue affecting privacy; rfc5246 recommends a lifetime of session IDs of less than 24 hours where afterwards the client attempts a resumption and only then the server falls back to a full handshake. The server can link both PSKs to the same user, session resumption caching allows a user identity to be shared with third-party trackers observing traffic on this server. Prior to TLS 1.3 this was a 0-RTT resumption which allows malicious actors to read all of the past communications using the same PSK. The flaw was detailed by rfc5077 in 2008 and web server default configurations have not widely adopted the changes."
VALIDATION_ERROR_SESSION_RESUMPTION_CACHING_TLS1_3 = "Session Resumption (caching) This server has a privacy issue; unrestricted use of session resumption mechanisms and can be shared with third-party trackers. TLS1.3 lifetime of session IDs offers duration up to seven days where afterwards the client attempts a 1-RTT resumption and the server falls back to a full handshake. The server can link both PSKs to the same user, while the user’s resumption lifetime is prolonged with the new PSK and not issued with any new unique identifier. This vulnerability was disclosed by the University of Hamburg in 2018 based on prior works by Dominik Herrmann, Christian Banse, and H. Federrath in 2013"
VALIDATION_ERROR_SESSION_RESUMPTION_TICKETS = "Session Resumption (tickets) A single key is used for the sessions of multiple users and is intended to mitigate privacy concerns of individual tracking, though a ticket identifier can be reused by a malicious actor for multiple or subsequent connections and decrypt all messages as resumed connections don't perform any Diffie-Hellman exchange, so they don't offer Forward Secrecy against the compromise of the STEK. This vulnerability was first identified by Adam Langley in 2013 which was built on works by M. Perry. in 2012"
VALIDATION_ERROR_CLIENT_RENEGOTIATION = "This server does not properly associate renegotiation handshakes with an existing connection, which allows manipulator-in-the-middle to insert data into HTTPS sessions by sending an unauthenticated request that is processed by a server in a post-renegotiation context.  The flaw was detailed by rfc5746 in 2010 and web server default configurations have not widely adopted the changes."
VALIDATION_ERROR_COMPRESSION_SUPPORT = 'This webserver offers TLS compression so that when a client also supports compression several known exploits exist that allow an attacker to perform session hijacking on an authenticated session. BEAST (2012), CRIME (2012), and BREACH (2013) are the well known attacks however various lesser known attacks exist such as "ssl, gone in 30 seconds" (2013) and other related Information Leakage Vulnerabilities'
VALIDATION_ERROR_EXPOSED_PRIVATE_KEY = "Your private key is exposed; Attackers in possession of the private key can impersonate the website, eavesdrop on encrypted traffic they have copied, or digitally sign malware on your behalf and distribute to target systems as you identified as the attacker"
VALIDATION_ERROR_VERSION_INTERFERENCE_CURRENT = 'Your server is not configured to accept clients that only support the current TLS version {current_version} and these clients browsers configured for privacy (and/or highest security) will be shown an error "ERR_SSL_VERSION_INTERFERENCE" and not negotiate a secure connection to your server.'
VALIDATION_ERROR_VERSION_INTERFERENCE_COMMON = 'Your server is not configured to accept clients that only support the common common TLS version {common_version} (You may be limited to older or only the newest versions) and these client browsers not yet configured for the latest TLS version {current_version} will be shown an error "ERR_SSL_VERSION_INTERFERENCE" and not negotiate a secure connection to your server.'
VALIDATION_ERROR_VERSION_INTERFERENCE_OLD = 'Your server is not configured to accept clients that only support TLS version {old_version} or older, these clients will be shown an error "ERR_SSL_VERSION_INTERFERENCE" and not negotiate a secure connection to your server.'
VALIDATION_ERROR_VERSION_INTERFERENCE_OBSOLETE = 'Your server is not configured to accept clients that only support obsolete TLS versions, these clients will be shown a error "ERR_SSL_VERSION_INTERFERENCE" and not negotiate a secure connection to your server.'
VALIDATION_ERROR_MISSING_ROOT_CA_AKI = "The intermediate Certificate with serial number {serial_number} has no Authority Key Identifier (AKI) which indicates either it was intended to be the Root CA and was not in the Trust Store, or it may have been issued invalid without an AKI, or the server provided a malformed Certificate. Without an AKI a valid Certificate chain can not be formed and there is not verifiable trust anchor. The Server Certificate is considered invalid, fake, or malicious."


class TransportError(ConnectionError):
    """Used when Transport class specific issues are encountered that are not validation related"""


class EvaluationNotRelevant(Exception):
    pass


class NoLogEvaluation(Exception):
    pass


class ValidationError(ValueError):
    def __init__(self, message: str = None, openssl_errno: int = None):
        if openssl_errno in X509_MESSAGES.keys():
            if message is None:
                message = X509_MESSAGES[openssl_errno]
            if isinstance(message, str):
                message += "\n" + X509_MESSAGES[openssl_errno]
        super().__init__(message)
        self.openssl_errno = openssl_errno
