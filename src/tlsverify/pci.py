__module__ = 'tlsverify.pci'

PCIDSS_VER = '3.2.1'
PCI_DSS_WEAK_KEY_SIZE = {
    'RSA': 2048,
    'DSA': 2048,
    'EC': 256,
    'DH': 256,
}
PCI_DSS_WEAK_CIPHER_BITS = 128
PCIDSS_NON_COMPLIANCE_WEAK_KEY_RSA = f'PCI DSS version {PCIDSS_VER} compliance requires RSA public key bits to greater than {PCI_DSS_WEAK_KEY_SIZE["RSA"]}'
PCIDSS_NON_COMPLIANCE_WEAK_KEY_DSA = f'PCI DSS version {PCIDSS_VER} compliance requires DSA public key bits to greater than {PCI_DSS_WEAK_KEY_SIZE["DSA"]}'
PCIDSS_NON_COMPLIANCE_WEAK_KEY_EC = f'PCI DSS version {PCIDSS_VER} compliance requires Elliptic curve public key bits to greater than {PCI_DSS_WEAK_KEY_SIZE["EC"]}'
PCIDSS_NON_COMPLIANCE_WEAK_KEY_DH = f'PCI DSS version {PCIDSS_VER} compliance requires Diffie-Hellman exchange public key bits to greater than {PCI_DSS_WEAK_KEY_SIZE["DH"]}'
PCIDSS_NON_COMPLIANCE_WEAK_PROTOCOL = f'PCI DSS version {PCIDSS_VER} compliance requires deprecated and known weak TLS protocols are not supported'
PCIDSS_NON_COMPLIANCE_CIPHER = f'PCI DSS version {PCIDSS_VER} compliance requires cipher bits to greater than {PCI_DSS_WEAK_CIPHER_BITS}, not be of Anonymous key exchange suites, Exchange ciphers, or other known weak ciphers as thy are discovered'
PCIDSS_NON_COMPLIANCE_KNOWN_VULNERABILITIES = f'PCI DSS version {PCIDSS_VER} compliance requires that no known vulnerabilities are present' # e.g. Compression, Insecure renegotiation, etc
PCIDSS_NON_COMPLIANCE_CA_TRUST = f'PCI DSS version {PCIDSS_VER} compliance requires a complete Certificate chain with verified trust anchor'
PCIDSS_NON_COMPLIANCE_WEAK_ALGORITHMS = f'PCI DSS version {PCIDSS_VER} compliance requires deprecated and known weak algorithms are not supported'
VALIDATION_CA_TRUST = 'pci_ca_trust'
VALIDATION_WEAK_KEY = 'pci_weak_key'
VALIDATION_WEAK_CIPHER = 'pci_weak_cipher'
VALIDATION_WEAK_PROTOCOL = 'pci_weak_protocol'
VALIDATION_DEPRECATED_ALGO = 'pci_deprecated_algo'
VALIDATION_KNOWN_VULN_COMPRESSION = 'pci_vuln_compression'
VALIDATION_KNOWN_VULN_RENEGOTIATION = 'pci_vuln_renegotiation'
VALIDATION_KNOWN_VULN_RESUMPTION_TICKETS = 'pci_vuln_session_resumption_tickets'
VALIDATION_KNOWN_VULN_RESUMPTION_CACHING = 'pci_vuln_session_resumption_caching'
