__module__ = 'tlsverify.fips'
__version__ = 'FIPS 140-2 (NIST SP800-131A transition mode)'

WEAK_KEY_SIZE = {
    'RSA': 2048,
    'DSA': 2048,
    'EC': 224,
    'DH': 224,
}
ALLOWED_DEPRECATED_TLS_CIPHERS = ['AES256-SHA', 'DES-CBC3-SHA', 'AES128-SHA']
ALLOWED_CIPHERS = ['AES256-GCM-SHA384', 'AES256-SHA256', 'AES256-SHA', 'DES-CBC3-SHA', 'AES128-GCM-SHA256', 'AES128-SHA256', 'AES128-SHA']
WEAK_CIPHER_BITS = 160
FIPS_NON_COMPLIANCE_WEAK_KEY_RSA = f'{__version__} compliance requires RSA public key bits to greater than {WEAK_KEY_SIZE["RSA"]}'
FIPS_NON_COMPLIANCE_WEAK_KEY_DSA = f'{__version__} compliance requires DSA public key bits to greater than {WEAK_KEY_SIZE["DSA"]}'
FIPS_NON_COMPLIANCE_WEAK_KEY_EC = f'{__version__} compliance requires Elliptic curve public key bits to greater than {WEAK_KEY_SIZE["EC"]}'
FIPS_NON_COMPLIANCE_WEAK_KEY_DH = f'{__version__} compliance requires Diffie-Hellman exchange public key bits to greater than {WEAK_KEY_SIZE["DH"]}'
FIPS_NON_COMPLIANCE_WEAK_PROTOCOL = f'{__version__} compliance requires TLS protocol 1.2 support'
FIPS_NON_COMPLIANCE_CIPHER = f'{__version__} compliance requires cipher bits to greater than {WEAK_CIPHER_BITS}, not be of Anonymous key exchange suites, Exchange ciphers, or many block ciphers'
FIPS_NON_COMPLIANCE_CA_TRUST = f'{__version__} compliance requires a complete Certificate chain with verified trust anchor and every Certificate must meet the requirements (not just the leaf)'
FIPS_NON_COMPLIANCE_MTLS = f'{__version__} compliance requires TLS1.2, Client authentication violates the new FIPS restrictions and cannot be used for TLS1.0/1.1 in transition mode'
VALIDATION_CA_TRUST = 'fips_ca_trust'
VALIDATION_WEAK_KEY = 'fips_weak_key'
VALIDATION_WEAK_CIPHER = 'fips_weak_cipher'
VALIDATION_WEAK_PROTOCOL = 'fips_weak_protocol'
VALIDATION_MTLS = 'fips_mtls'
