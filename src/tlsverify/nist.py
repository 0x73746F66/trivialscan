__module__ = 'tlsverify.nist'
__version__ = 'NIST SP800-131A (strict mode)'

WEAK_KEY_SIZE = {
    'RSA': 2048,
    'DSA': 2048,
    'EC': 256,
    'DH': 256,
}
ALLOWED_CIPHERS = ['AES256-GCM-SHA384', 'AES256-SHA256', 'AES256-SHA', 'DES-CBC3-SHA', 'AES128-GCM-SHA256', 'AES128-SHA256', 'AES128-SHA']
WEAK_CIPHER_BITS = 160
NIST_NON_COMPLIANCE_WEAK_KEY_RSA = f'{__version__} compliance requires RSA public key bits to greater than {WEAK_KEY_SIZE["RSA"]}'
NIST_NON_COMPLIANCE_WEAK_KEY_DSA = f'{__version__} compliance requires DSA public key bits to greater than {WEAK_KEY_SIZE["DSA"]}'
NIST_NON_COMPLIANCE_WEAK_KEY_EC = f'{__version__} compliance requires Elliptic curve public key bits to greater than {WEAK_KEY_SIZE["EC"]}'
NIST_NON_COMPLIANCE_WEAK_KEY_DH = f'{__version__} compliance requires Diffie-Hellman exchange public key bits to greater than {WEAK_KEY_SIZE["DH"]}'
NIST_NON_COMPLIANCE_WEAK_PROTOCOL = f'{__version__} compliance requires deprecated and known weak TLS protocols are not supported'
NIST_NON_COMPLIANCE_CIPHER = f'{__version__} compliance requires cipher bits to greater than {WEAK_CIPHER_BITS}, not be of Anonymous key exchange suites, Exchange ciphers, or many block ciphers'
NIST_NON_COMPLIANCE_CA_TRUST = f'{__version__} compliance requires a complete Certificate chain with verified trust anchor'
NIST_NON_COMPLIANCE_MTLS = f'{__version__} compliance requires client certificate authentication'
VALIDATION_CA_TRUST = 'nist_ca_trust'
VALIDATION_WEAK_KEY = 'nist_weak_key'
VALIDATION_WEAK_CIPHER = 'nist_weak_cipher'
VALIDATION_WEAK_PROTOCOL = 'nist_weak_protocol'
VALIDATION_MTLS = 'nist_mtls'
