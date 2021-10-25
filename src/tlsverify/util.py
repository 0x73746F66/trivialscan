import logging
import string
import random
from io import BytesIO
from datetime import datetime, timedelta
from urllib.request import urlretrieve
from urllib.parse import urlparse
from binascii import hexlify
from pathlib import Path
import requests
import validators
from cryptography import x509
from cryptography.x509 import Certificate, extensions, SubjectAlternativeName, DNSName
from OpenSSL import SSL
from OpenSSL.crypto import X509, FILETYPE_PEM, dump_certificate
from certvalidator import CertificateValidator, ValidationContext
from rich.style import Style
from rich.console import Console
from dns import resolver, dnssec, rdatatype, message, query, name as dns_name
from dns.exception import DNSException, Timeout as DNSTimeoutError
from dns.resolver import NoAnswer
from tldextract import TLDExtract
from crlite_query import CRLiteDB, IntermediatesDB, CRLiteQuery


__module__ = 'tlsverify.util'

logger = logging.getLogger(__name__)

CRLITE_URL = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/cert-revocations/records" # https://github.com/mozilla/moz_crlite_query/blob/main/crlite_query/query_cli.py
VALIDATION_OID = {
    '2.16.840.1.114414.1.7.23.1': 'DV',
    '1.3.6.1.4.1.46222.1.10': 'DV',
    '1.3.6.1.4.1.34697.1.1': 'EV',
    '2.16.840.1.113839.0.6.3': 'EV',
    '2.16.792.3.0.3.1.1.5': 'EV',
    '1.3.6.1.4.1.5237.1.1.3': 'EV',
    '2.16.840.1.101.3.2.1.1.5': 'EV',
    '1.3.6.1.4.1.30360.3.3.3.3.4.4.3.0': 'EV',
    '1.3.6.1.4.1.46222.1.1': 'EV',
    '1.3.6.1.4.1.311.60': 'EV',
    '1.3.6.1.4.1.48679.100': 'EV',
    '1.3.6.1.4.1.55594.1.1.1': 'EV',
    '1.3.6.1.4.1.4788.2.200.1': 'EV',
    '1.3.6.1.4.1.4788.2.202.1': 'EV',
    '1.3.6.1.4.1.31247.1.3': 'EV',
    '1.3.6.1.4.1.52331.2': 'EV',
    '2.16.840.1.114414.1.7.23.2': 'OV',
    '2.16.792.3.0.3.1.1.2': 'OV',
    '1.3.6.1.4.1.46222.1.20': 'OV',
    '2.23.140.1.2.1': 'DV',
    '2.23.140.1.2.2': 'OV',
    '2.23.140.1.2.3': 'EV',
}
# https://ccadb-public.secure.force.com/ccadb/AllCAAIdentifiersReport
CAA_DOMAINS = {
    "camerfirma.com": ["AC Camerfirma, S.A."],
    "actalis.it": ["Actalis"],
    "amazon.com": ["Amazon Trust Services"],
    "amazontrust.com": ["Amazon Trust Services"],
    "awstrust.com": ["Amazon Trust Services"],
    "amazonaws.com": ["Amazon Trust Services"],
    "aws.amazon.com": ["Amazon Trust Services"],
    "pki.apple.com": ["Apple Public Server ECC CA 11 - G1","Apple Public Server ECC CA 12 - G1","Apple Public Server RSA CA 11 - G1","Apple Public Server RSA CA 12 - G1"],
    "certum.pl": ["Asseco Data Systems S.A. (previously Unizeto Certum)"],
    "certum.eu": ["Asseco Data Systems S.A. (previously Unizeto Certum)"],
    "yandex.ru": ["Asseco Data Systems S.A. (previously Unizeto Certum)"],
    "atos.net": ["Atos"],
    "firmaprofesional.com": ["Autoridad de Certificacion Firmaprofesional"],
    "anf.es": ["Autoridad de Certificación (ANF AC)"],
    "buypass.com": ["Buypass"],
    "buypass.no": ["Buypass"],
    "certicamara.com": ["Certicámara"],
    "certigna.fr": ["Dhimyotis / Certigna","Certigna Entity Code Signing CA","Certigna Identity CA","Certigna Identity Plus CA","Certigna Services CA"],
    "www.certinomis.com": ["Certinomis / Docapost"],
    "www.certinomis.fr": ["Certinomis / Docapost"],
    "certsign.ro": ["certSIGN"],
    "cfca.com.cn": ["China Financial Certification Authority (CFCA)"],
    "pki.hinet.net": ["Chunghwa Telecom"],
    "tls.hinet.net": ["Chunghwa Telecom"],
    "eca.hinet.net": ["Chunghwa Telecom"],
    "epki.com.tw": ["Chunghwa Telecom"],
    "publicca.hinet.net": ["Chunghwa Telecom"],
    "cisco.com": ["Cisco","Cisco XSSL-R2"],
    "Comsign.co.il": ["ComSign"],
    "Comsign.co.uk": ["ComSign"],
    "Comsigneurope.com": ["ComSign"],
    "aoc.cat": ["Consorci Administració Oberta de Catalunya (Consorci AOC, CATCert)"],
    "jcsinc.co.jp": ["Cybertrust Japan / JCSI","Cybertrust Japan SureCode CA G1","Cybertrust Japan SureCode CA G2","Cybertrust Japan SureCode CA G3","Cybertrust Japan SureCode CA G4","Cybertrust Japan SureCode EV CA G1","Cybertrust Japan SureCode EV CA G2","Cybertrust Japan SureCode EV CA G3","Cybertrust Japan SureCode EV CA G4","Cybertrust Japan SureMail CA G5","Cybertrust Japan SureMail CA G6","Cybertrust Japan SureServer CA G4","Cybertrust Japan SureServer CA G5","Cybertrust Japan SureServer CA G6","Cybertrust Japan SureServer CA G7","Cybertrust Japan SureServer CA G8","Cybertrust Japan SureServer EV CA G3","Cybertrust Japan SureServer EV CA G4","Cybertrust Japan SureServer EV CA G5","Cybertrust Japan SureServer EV CA G6","Cybertrust Japan SureServer EV CA G7","Cybertrust Japan SureServer EV CA G8","Cybertrust Japan SureServer EV CA G9","Cybertrust Japan SureTime CA G1","Cybertrust Japan SureTime CA G2","Cybertrust Japan SureTime CA G3","Cybertrust Japan SureTime CA G4"],
    "dtrust.de": ["D-TRUST"],
    "d-trust.de": ["D-TRUST"],
    "dtrust.net": ["D-TRUST"],
    "d-trust.net": ["D-TRUST"],
    "telesec.de": ["Deutsche Telekom Security GmbH"],
    "pki.dfn.de": ["Deutsche Telekom Security GmbH"],
    "dfn.de": ["Deutsche Telekom Security GmbH"],
    "digicert.com": ["QuoVadis","Symantec","Symantec / GeoTrust","Symantec / VeriSign","DigiCert", "DigiCert Inc"],
    "geotrust.com": ["Symantec","Symantec / GeoTrust","Symantec / VeriSign","QuoVadis","DigiCert", "DigiCert Inc"],
    "rapidssl.com": ["DigiCert","QuoVadis","Symantec","Symantec / GeoTrust","Symantec / VeriSign", "DigiCert Inc"],
    "digitalcertvalidation.com": ["Symantec","Symantec / GeoTrust","Symantec / VeriSign","QuoVadis","DigiCert", "DigiCert Inc"],
    "volusion.digitalcertvalidation.com": ["Symantec","Symantec / GeoTrust","Symantec / VeriSign","DigiCert", "DigiCert Inc"],
    "stratossl.digitalcertvalidation.com": ["Symantec","Symantec / GeoTrust","Symantec / VeriSign","DigiCert", "DigiCert Inc"],
    "intermediatecertificate.digitalcertvalidation.com": ["DigiCert","Symantec","Symantec / GeoTrust","Symantec / VeriSign", "DigiCert Inc"],
    "1and1.digitalcertvalidation.com": ["Symantec","Symantec / GeoTrust","Symantec / VeriSign","DigiCert","Digidentity B.V.", "DigiCert Inc"],
    "digidentity.com": ["Digidentity BV PKIoverheid Burger CA - 2021","Digidentity BV PKIoverheid Organisatie Server CA - G3","Digidentity BV PKIoverheid Organisatie Server CA - G3","Digidentity BV PKIoverheid Organisatie Services CA - 2021","Digidentity Organisatie CA - G2","Digidentity PKIoverheid Organisatie Server CA - G3","Digidentity PKIoverheid Server CA 2020"],
    "disig.sk": ["Disig, a.s."],
    "globaltrust.eu": ["e-commerce monitoring GmbH"],
    "e-tugra.com.tr": ["E-Tugra"],
    "e-tugra.com": ["E-Tugra"],
    "etugra.com": ["E-Tugra"],
    "etugra.com.tr": ["E-Tugra"],
    "edicomgroup.com": ["EDICOM"],
    "emsign.com": ["eMudhra Technologies Limited"],
    "entrust.net": ["Entrust"],
    "affirmtrust.com": ["Entrust"],
    "fina.hr": ["Financijska agencija (Fina)"],
    "gdca.com.cn": ["Global Digital Cybersecurity Authority Co., Ltd. (Formerly Guang Dong Certificate Authority (GDCA))"],
    "globalsign.com": ["GlobalSign nv-sa"],
    "godaddy.com": ["GoDaddy"],
    "starfieldtech.com": ["GoDaddy"],
    "pki.goog": ["Google Trust Services LLC"],
    "google.com": ["Google Trust Services LLC"],
    "eCert.gov.hk": ["Government of Hong Kong (SAR), Hongkong Post, Certizen"],
    "hongkongpost.gov.hk": ["Government of Hong Kong (SAR), Hongkong Post, Certizen"],
    "gpki.go.kr": ["Government of Korea, KLID"],
    "accv.es": ["Government of Spain, Autoritat de Certificació de la Comunitat Valenciana (ACCV)"],
    "fnmt.es": ["Government of Spain, Fábrica Nacional de Moneda y Timbre (FNMT)"],
    "efos.se": ["Government of Sweden (Försäkringskassan)"],
    "myndighetsca.se": ["Government of Sweden (Försäkringskassan)"],
    "gca.nat.gov.tw": ["Government of Taiwan, Government Root Certification Authority (GRCA)"],
    "www.pkioverheid.nl": ["Staat der Nederlanden Domein Server CA 2020","Government of The Netherlands, PKIoverheid (Logius)","QuoVadis CSP - PKI Overheid CA - G2","QuoVadis PKIoverheid EV CA","QuoVadis PKIoverheid Organisatie Server CA - G3","QuoVadis PKIoverheid Organisatie Server CA - G3","QuoVadis PKIoverheid Server CA 2020","QuoVadis PKIoverheid Server CA 2020"],
    "tuntrust.tn": ["Government of Tunisia, Agence National de Certification Electronique / National Digital Certification Agency (ANCE/NDCA)"],
    "kamusm.gov.tr": ["Government of Turkey, Kamu Sertifikasyon Merkezi (Kamu SM)"],
    "harica.gr": ["HARICA"],
    "identrust.com": ["IdenTrust Commercial Root CA 1","IdenTrust Services, LLC"],
    "letsencrypt.org": ["R3", "R4", "Internet Security Research Group","ISRG Root X1"],
    "izenpe.com": ["CA de Certificados SSL EV","Izenpe S.A."],
    "izenpe.eus": ["CA de Certificados SSL EV","Izenpe S.A."],
    "jprs.jp": ["JPRS Domain Validation Authority - G3","JPRS Domain Validation Authority - G3","JPRS Domain Validation Authority - G3","JPRS Domain Validation Authority - G4","JPRS Organization Validation Authority - G3","JPRS Organization Validation Authority - G3","JPRS Organization Validation Authority - G3","JPRS Organization Validation Authority - G4","KPN BV PKIoverheid Organisatie Server CA - G3"],
    "kpn.com": ["KPN BV PKIoverheid Organisatie Server CA - G3","KPN CM PKIoverheid EV CA","KPN Corporate Market CSP Organisatie CA - G2","KPN Corporate Market CSP Organisatie Services CA - G3","KPN PKIoverheid EV CA","KPN PKIoverheid EV CA","KPN PKIoverheid Organisatie CA - G2","KPN PKIoverheid Organisatie CA - G2","KPN PKIoverheid Organisatie CA - G2","KPN PKIoverheid Organisatie Persoon CA - G3","KPN PKIoverheid Organisatie Persoon CA - G3","KPN PKIoverheid Organisatie Server CA - G3","KPN PKIoverheid Organisatie Server CA - G3","KPN PKIoverheid Organisatie Services CA - G3","KPN PKIoverheid Organisatie Services CA - G3","KPN PKIoverheid Server CA 2020","KPN PKIoverheid Server CA 2020"],
    "elektronicznypodpis.pl": ["Krajowa Izba Rozliczeniowa S.A. (KIR)"],
    "e-szigno.hu": ["Microsec Ltd."],
    "microsoft.com": ["Microsoft Corporation","Microsoft RSA TLS Issuing AOC CA 02"],
    "multicert.com": ["MULTICERT"],
    "certificate.naver.com": ["NAVER Cloud"],
    "netlock.hu": ["NETLOCK Kft."],
    "netlock.net": ["NETLOCK Kft."],
    "netlock.eu": ["NETLOCK Kft."],
    "web.com": ["Network Solutions","Network Solutions Certificate Authority"],
    "networksolutions.com": ["Network Solutions","Network Solutions Certificate Authority"],
    "wisekey.com": ["OISTE"],
    "hightrusted.com": ["OISTE"],
    "certifyid.com": ["OISTE"],
    "oiste.org": ["OISTE"],
    "oaticerts.com": ["Open Access Technology International, Inc. (OATI)"],
    "quovadisglobal.com": ["QuoVadis","QuoVadis CSP - PKI Overheid EV CA","QuoVadis CSP - PKI Overheid CA - G2","QuoVadis PKIoverheid EV CA","QuoVadis PKIoverheid Organisatie Server CA - G3","QuoVadis PKIoverheid Organisatie Server CA - G3","QuoVadis PKIoverheid Organisatie Services CA - G3","QuoVadis PKIoverheid Server CA 2020","QuoVadis PKIoverheid Server CA 2020"],
    "digicert.ne.jp": ["QuoVadis"],
    "cybertrust.ne.jp": ["QuoVadis","Cybertrust Japan / JCSI","Cybertrust Japan SureCode CA G1","Cybertrust Japan SureCode CA G2","Cybertrust Japan SureCode CA G3","Cybertrust Japan SureCode CA G4","Cybertrust Japan SureCode EV CA G1","Cybertrust Japan SureCode EV CA G2","Cybertrust Japan SureCode EV CA G3","Cybertrust Japan SureCode EV CA G4","Cybertrust Japan SureMail CA G5","Cybertrust Japan SureMail CA G6","Cybertrust Japan SureServer CA G4","Cybertrust Japan SureServer CA G5","Cybertrust Japan SureServer CA G6","Cybertrust Japan SureServer CA G7","Cybertrust Japan SureServer CA G8","Cybertrust Japan SureServer EV CA G3","Cybertrust Japan SureServer EV CA G4","Cybertrust Japan SureServer EV CA G5","Cybertrust Japan SureServer EV CA G6","Cybertrust Japan SureServer EV CA G7","Cybertrust Japan SureServer EV CA G8","Cybertrust Japan SureServer EV CA G9","Cybertrust Japan SureTime CA G1","Cybertrust Japan SureTime CA G2","Cybertrust Japan SureTime CA G3","Cybertrust Japan SureTime CA G4"],
    "symantec.com": ["QuoVadis","DigiCert","Symantec","Symantec / GeoTrust","Symantec / VeriSign", "DigiCert Inc"],
    "thawte.com": ["QuoVadis","Symantec","Symantec / GeoTrust","Symantec / VeriSign","DigiCert", "DigiCert Inc"],
    "secomtrust.net": ["SECOM Trust Systems CO., LTD."],
    "sectigo.com": ["Sectigo"],
    "comodo.com": ["Sectigo"],
    "comodoca.com": ["Sectigo"],
    "usertrust.com": ["Sectigo"],
    "trust-provider.com": ["Sectigo"],
    "trustwave.com": ["SecureTrust"],
    "securetrust.com": ["SecureTrust"],
    "sheca.com": ["Shanghai Electronic Certification Authority Co., Ltd."],
    "imtrust.cn": ["Shanghai Electronic Certification Authority Co., Ltd."],
    "wwwtrust.cn": ["Shanghai Electronic Certification Authority Co., Ltd."],
    "skidsolutions.eu": ["SK ID Solutions AS"],
    "ssl.com": ["SSL.com"],
    "pkioverheid.nl": ["Staat der Nederlanden Domein Server CA 2020"],
    "admin.ch": ["Swiss BIT, Swiss Federal Office of Information Technology, Systems and Telecommunication (FOITT)"],
    "swisssign.com": ["SwissSign AG"],
    "swisssign.net": ["SwissSign AG"],
    "swissign.com": ["SwissSign AG"],
    "swisssign.ch": ["SwissSign AG"],
    "swisssign.li": ["SwissSign AG"],
    "swissign.li": ["SwissSign AG"],
    "swisssign.org": ["SwissSign AG"],
    "swisssign.biz": ["SwissSign AG"],
    "swisstsa.ch": ["SwissSign AG"],
    "swisstsa.li": ["SwissSign AG"],
    "digitalid.ch": ["SwissSign AG"],
    "digital-id.ch": ["SwissSign AG"],
    "zert.ch": ["SwissSign AG"],
    "rootsigning.com": ["SwissSign AG"],
    "root-signing.ch": ["SwissSign AG"],
    "ssl-certificate.ch": ["SwissSign AG"],
    "managed-pki.ch": ["SwissSign AG"],
    "managed-pki.de": ["SwissSign AG"],
    "swissstick.com": ["SwissSign AG"],
    "swisssigner.ch": ["SwissSign AG"],
    "pki-posta.ch": ["SwissSign AG"],
    "pki-poste.ch": ["SwissSign AG"],
    "pki-post.ch": ["SwissSign AG"],
    "trustdoc.ch": ["SwissSign AG"],
    "trustsign.ch": ["SwissSign AG"],
    "swisssigner.com": ["SwissSign AG"],
    "postsuisseid.ch": ["SwissSign AG"],
    "suisseid-service.ch": ["SwissSign AG"],
    "signdemo.com": ["SwissSign AG"],
    "sirb.com": ["SwissSign AG"],
    "twca.com.tw": ["Taiwan-CA Inc. (TWCA)"],
    "telia.com": ["Telia Company"],
    "telia.fi": ["Telia Company"],
    "telia.se": ["Telia Company"],
    "trustcor.ca": ["TrustCor Systems"],
    "trustfactory.net": ["TrustFactory Client Issuing Certificate Authority","TrustFactory SSL Issuing Certificate Authority","TrustFactory(Pty)Ltd"],
    "gtlsca.nat.gov.tw": ["行政院/政府伺服器數位憑證管理中心 - G1"]
}
VALIDATION_TYPES = {
    'DV': 'Domain Validation (DV)',
    'OV': 'Organization Validation (OV)',
    'EV': 'Extended Validation (EV)',
}
X509_DATE_FMT = r'%Y%m%d%H%M%SZ'
WEAK_KEY_SIZE = {
    'RSA': 1024,
    'DSA': 2048,
    'EC': 160,
}
KNOWN_WEAK_KEYS = {
    'RSA': 'The use RSA Encryption is considered vulnerable in certain context. 2000: Factorization of a 512-bit RSA Modulus, essentially derive a private key knowing only the public key. Verified bt EFF in 2001. Later in 2009 factorization of up to 1024-bit keys',
    'DSA': 'The use DSA Encryption is considered vulnerable. 1999: HPL Laboratories demonstrated lattice attacks on DSA, a non-trivial example of the known message attack that is a total break and message forgery technique. 2010 Dimitrios Poulakis demonstrated a lattice reduction technique for single or multiple message forgery',
    'EC': 'The use Elliptic-curve Encryption is considered vulnerable in certain context. 2010 Dimitrios Poulakis demonstrated a lattice reduction technique to attack ECDSA for single or multiple message forgery',
}
KNOWN_WEAK_SIGNATURE_ALGORITHMS = {
    'sha1WithRSAEncryption': 'The use of SHA1 with RSA Encryption is considered vulnerable. Macquarie University Australia 2009: identified vulnerabilities to collision attacks, later in 2017 Marc Stevens demonstrated collision proofs',
    'md5WithRSAEncryption': 'The use of MD5 with RSA Encryption is considered vulnerable. Arjen Lenstra and Benne de Weger 2005: vulnerable to hash collision attacks',
    'md2WithRSAEncryption': 'The use of MD2 with RSA Encryption is considered vulnerable. Rogier, N. and Chauvaud, P. in 1995: vulnerable to collision, later preimage resistance, and second-preimage resistance attacks were demonstrated at BlackHat 2008 by Mark Twain',
}
OPENSSL_VERSION_LOOKUP = {
    768: 'SSLv3',
    769: 'TLSv1',
    770: 'TLSv1.1',
    771: 'TLSv1.2',
    772: 'TLSv1.3',
}
WEAK_PROTOCOL = {
    'SSLv2': 'SSLv2 Deprecated in 2011 (rfc6176) with undetectable manipulator-in-the-middle exploits',
    'SSLv3': 'SSLv3 Deprecated in 2015 (rfc7568) mainly due to POODLE, a manipulator-in-the-middle exploit',
    'TLSv1': 'TLSv1 2018 deprecated by PCI Council. Also in 2018, Apple, Google, Microsoft, and Mozilla jointly announced deprecation. Officially deprecated in 2020 (rfc8996)',
    'TLSv1.1': 'TLSv1.1 No longer supported by Firefox 24 or newer and Chrome 29 or newer. Deprecated in 2020 (rfc8996)',
}
OCSP_RESP_STATUS = {
    0: 'Successful',
    1: 'Malformed Request',
    2: 'Internal Error',
    3: 'Try Later',
    4: 'Signature Required',
    5: 'Unauthorized',
}
OCSP_CERT_STATUS = {
    0: 'Good',
    1: 'Revoked',
    2: 'Unknown',
}
SESSION_CACHE_MODE = {
    SSL.SESS_CACHE_OFF: 'no caching',
    SSL.SESS_CACHE_CLIENT: 'session_resumption_tickets',
    SSL.SESS_CACHE_SERVER: 'session_resumption_caching',
    SSL.SESS_CACHE_BOTH: 'session_resumption_both',
}
NOT_KNOWN_WEAK_CIPHERS = [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES256-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES128-SHA256',
    'DHE-DSS-AES256-GCM-SHA384',
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES256-SHA256',
    'DHE-DSS-AES256-SHA256',
    'DHE-DSS-AES128-GCM-SHA256',
    'DHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES128-SHA256',
    'DHE-DSS-AES128-SHA256',
]
STRONG_CIPHERS = [
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_CCM_8_SHA256',
    'TLS_AES_128_CCM_SHA2',
]
DNSSEC_ALGORITHMS = {
    1: 'RSA/MD5',
    3: 'DSA/SHA-1',
    5: 'RSA/SHA-1',
    6: 'DSA-NSEC3-SHA1',
    7: 'RSASHA1-NSEC3-SHA1',
    8: 'RSA/SHA-256',
    10: 'RSA/SHA-512',
    12: 'GOST R 34.10-2001',
    13: 'ECDSA/SHA-256',
    14: 'ECDSA/SHA-384',
    15: 'Ed25519',
    16: 'Ed448',
}
WEAK_DNSSEC_ALGORITHMS = {
    'RSA/MD5': 'DNSSEC Algorithm RSA/MD5 was deprecated in 2005',
    'DSA/SHA-1': 'DNSSEC Algorithm DSA/SHA-1 was deprecated in 2004',
    'RSA/SHA-1': KNOWN_WEAK_SIGNATURE_ALGORITHMS['sha1WithRSAEncryption'],
    'DSA-NSEC3-SHA1': 'DNSSEC Algorithm was DSA-NSEC3-SHA1 deprecated in 2008',
    'GOST R 34.10-2001': 'DNSSEC Algorithm GOST R 34.10-2001 was deprecated in 2010',
}
STRONG_DNSSEC_ALGORITHMS = [
    'ECDSA/SHA-384',
    'Ed25519',
    'Ed448',
]

def filter_valid_files_urls(inputs :list[str], tmp_path_prefix :str = '/tmp'):
    ret = set()
    for test in inputs:
        if test is None:
            return False
        file_path = Path(test)
        if file_path.is_file() is False and validators.url(test) is not True:
            return False
        if file_path.is_file():
            ret.add(test)
            continue
        if validators.url(test) is True:
            r = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
            local_path = f'{tmp_path_prefix}/tlsverify-{r}'
            try:
                urlretrieve(test, local_path)
            except Exception as ex:
                logger.error(ex, stack_info=True)
            file_path = Path(local_path)
            if not file_path.is_file():
                return False
            ret.add(local_path)
    return list(ret)

def convert_decimal_to_serial_bytes(decimal :int):
    # add leading 0
    a = "0%x" % decimal
    # force even num bytes, remove leading 0 if necessary
    b = a[1:] if len(a)%2==1 else a
    return format(':'.join(s.encode('utf8').hex().lower() for s in b))

def is_self_signed(cert :Certificate) -> bool:
    certificate_is_self_signed = False
    authority_key_identifier = None
    subject_key_identifier = None
    try:
        authority_key_identifier = hexlify(cert.extensions.get_extension_for_class(extensions.AuthorityKeyIdentifier).value.key_identifier).decode('utf-8')
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
        certificate_is_self_signed = True
    try:
        subject_key_identifier = hexlify(cert.extensions.get_extension_for_class(extensions.SubjectKeyIdentifier).value.digest).decode('utf-8')
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
        certificate_is_self_signed = True
    if subject_key_identifier == authority_key_identifier:
        certificate_is_self_signed = True
    return certificate_is_self_signed

def get_san(cert :Certificate) -> list:
    san = []
    try:
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value.get_values_for_type(DNSName)
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    return san

def get_basic_constraints(cert :Certificate) -> tuple[bool, int]:
    basic_constraints = None
    try:
        basic_constraints = cert.extensions.get_extension_for_class(extensions.BasicConstraints).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    if not isinstance(basic_constraints, extensions.BasicConstraints):
        return None, None
    return basic_constraints.ca, basic_constraints.path_length

def key_usage_exists(cert :Certificate, key :str) -> bool:
    key_usage = None
    ext_key_usage = None
    try:
        key_usage = cert.extensions.get_extension_for_class(extensions.KeyUsage).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    try:
        ext_key_usage = cert.extensions.get_extension_for_class(extensions.ExtendedKeyUsage).value
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    if key_usage is None and ext_key_usage is None:
        logger.warning('no key usages could not be found')
        return False
    if isinstance(key_usage, extensions.KeyUsage) and hasattr(key_usage, key) and getattr(key_usage, key) is True:
        return True
    if isinstance(ext_key_usage, extensions.ExtendedKeyUsage) and key in [usage._name for usage in ext_key_usage if hasattr(usage, '_name')]:
        return True
    return False

def get_valid_certificate_extensions(cert :Certificate) -> list[extensions.Extension]:
    certificate_extensions = []
    for ext in cert.extensions:
        if isinstance(ext.value, extensions.UnrecognizedExtension):
            continue
        certificate_extensions.append(ext.value)
    return certificate_extensions

def get_certificate_extensions(cert :Certificate) -> list[dict]:
    certificate_extensions = []
    for ext in cert.extensions:
        data = {
            'critical': ext.critical,
            'name': ext.oid._name # pylint: disable=protected-access
        }
        if isinstance(ext.value, extensions.UnrecognizedExtension):
            continue
        if isinstance(ext.value, extensions.CRLNumber):
            data[data['name']] = ext.value.crl_number
        if isinstance(ext.value, extensions.AuthorityKeyIdentifier):
            data[data['name']] = hexlify(ext.value.key_identifier).decode('utf-8')
            data['authority_cert_issuer'] = ', '.join([x.value for x in ext.value.authority_cert_issuer or []])
            data['authority_cert_serial_number'] = ext.value.authority_cert_serial_number
        if isinstance(ext.value, extensions.SubjectKeyIdentifier):
            data[data['name']] = hexlify(ext.value.digest).decode('utf-8')
        if isinstance(ext.value, (extensions.AuthorityInformationAccess, extensions.SubjectInformationAccess)):
            data[data['name']] = []
            for description in ext.value:
                data[data['name']].append({
                    'access_location': description.access_location.value,
                    'access_method': description.access_method._name, # pylint: disable=protected-access
                })
        if isinstance(ext.value, extensions.BasicConstraints):
            data['ca'] = ext.value.ca
            data['path_length'] = ext.value.path_length
        if isinstance(ext.value, extensions.DeltaCRLIndicator):
            data[data['name']] = ext.value.crl_number
        if isinstance(ext.value, (extensions.CRLDistributionPoints, extensions.FreshestCRL)):
            data[data['name']] = []
            for distribution_point in ext.value:
                data[data['name']].append({
                    'full_name': ', '.join([x.value for x in distribution_point.full_name or []]),
                    'relative_name': distribution_point.relative_name,
                    'reasons': distribution_point.reasons,
                    'crl_issuer': ', '.join([x.value for x in distribution_point.crl_issuer or []]),
                })
        if isinstance(ext.value, extensions.PolicyConstraints):
            data['policy_information'] = []
            data['user_notices'] = []
            for info in ext.value:
                if hasattr(info, 'require_explicit_policy'):
                    data['policy_information'].append({
                        'require_explicit_policy': info.require_explicit_policy,
                        'inhibit_policy_mapping': info.inhibit_policy_mapping,
                    })
                if hasattr(info, 'notice_reference'):
                    data['user_notices'].append({
                        'organization': info.notice_reference.organization,
                        'notice_numbers': info.notice_reference.notice_numbers,
                        'explicit_text': info.explicit_text,
                    })
        if isinstance(ext.value, extensions.ExtendedKeyUsage):
            data[data['name']] = [x._name for x in ext.value or []] # pylint: disable=protected-access
        if isinstance(ext.value, extensions.TLSFeature):
            data[data['name']] = []
            for feature in ext.value:
                if feature.value == 5:
                    data[data['name']].append('OCSP Must-Staple (rfc6066)')
                if feature.value == 17:
                    data[data['name']].append('multiple OCSP responses (rfc6961)')
        if isinstance(ext.value, extensions.InhibitAnyPolicy):
            data[data['name']] = ext.value.skip_certs
        if isinstance(ext.value, extensions.KeyUsage):
            data[data['name']] = []
            data['digital_signature'] = ext.value.digital_signature
            if ext.value.digital_signature:
                data[data['name']].append('digital_signature')
            data['content_commitment'] = ext.value.content_commitment
            if ext.value.content_commitment:
                data[data['name']].append('content_commitment')
            data['key_encipherment'] = ext.value.key_encipherment
            if ext.value.key_encipherment:
                data[data['name']].append('key_encipherment')
            data['data_encipherment'] = ext.value.data_encipherment
            if ext.value.data_encipherment:
                data[data['name']].append('data_encipherment')
            data['key_agreement'] = ext.value.key_agreement
            if ext.value.key_agreement:
                data[data['name']].append('key_agreement')
                data['decipher_only'] = ext.value.decipher_only
                if ext.value.decipher_only:
                    data[data['name']].append('decipher_only')
                data['encipher_only'] = ext.value.encipher_only
                if ext.value.encipher_only:
                    data[data['name']].append('encipher_only')
            data['key_cert_sign'] = ext.value.key_cert_sign
            if ext.value.key_cert_sign:
                data[data['name']].append('key_cert_sign')
            data['crl_sign'] = ext.value.crl_sign
            if ext.value.crl_sign:
                data[data['name']].append('crl_sign')
        if isinstance(ext.value, extensions.NameConstraints):
            data['permitted_subtrees'] = [x.value for x in ext.value.permitted_subtrees or []]
            data['excluded_subtrees'] = [x.value for x in ext.value.excluded_subtrees or []]
        if isinstance(ext.value, extensions.SubjectAlternativeName):
            data[data['name']] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.IssuerAlternativeName):
            data[data['name']] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.CertificateIssuer):
            data[data['name']] = [x.value for x in ext.value or []]
        if isinstance(ext.value, extensions.CRLReason):
            data[data['name']] = ext.value.reason
        if isinstance(ext.value, extensions.InvalidityDate):
            data[data['name']] = ext.value.invalidity_date
        if isinstance(ext.value, (extensions.PrecertificateSignedCertificateTimestamps, extensions.SignedCertificateTimestamps)):
            data[data['name']] = []
            for signed_cert_timestamp in ext.value:
                data[data['name']].append({
                    'version': signed_cert_timestamp.version.name,
                    'log_id': hexlify(signed_cert_timestamp.log_id).decode('utf-8'),
                    'timestamp': signed_cert_timestamp.timestamp,
                    'pre_certificate': signed_cert_timestamp.entry_type.value == 1,
                })
        if isinstance(ext.value, extensions.OCSPNonce):
            data[data['name']] = ext.value.nonce
        if isinstance(ext.value, extensions.IssuingDistributionPoint):
            data['full_name'] = ext.value.full_name
            data['relative_name'] = ext.value.relative_name
            data['only_contains_user_certs'] = ext.value.only_contains_user_certs
            data['only_contains_ca_certs'] = ext.value.only_contains_ca_certs
            data['only_some_reasons'] = ext.value.only_some_reasons
            data['indirect_crl'] = ext.value.indirect_crl
            data['only_contains_attribute_certs'] = ext.value.only_contains_attribute_certs
        certificate_extensions.append(data)
    return certificate_extensions

def gather_key_usages(cert :Certificate) -> tuple[list, list]:
    validator_key_usage = []
    validator_extended_key_usage = []
    for ext in get_valid_certificate_extensions(cert):
        if isinstance(ext, extensions.UnrecognizedExtension):
            continue
        if isinstance(ext, extensions.ExtendedKeyUsage):
            extended_usages = [x._name for x in ext or []] # pylint: disable=protected-access
            if 'serverAuth' in extended_usages:
                validator_extended_key_usage.append('server_auth')
        if isinstance(ext, extensions.TLSFeature):
            for feature in ext:
                if feature.value in [5, 17]:
                    validator_extended_key_usage.append('ocsp_signing')
        if isinstance(ext, extensions.KeyUsage):
            validator_key_usage += _extract_key_usage(ext)
    return validator_key_usage, validator_extended_key_usage

def _extract_key_usage(ext):
    validator_key_usage = []
    if ext.digital_signature:
        validator_key_usage.append('digital_signature')
    if ext.content_commitment:
        validator_key_usage.append('content_commitment')
    if ext.key_encipherment:
        validator_key_usage.append('key_encipherment')
    if ext.data_encipherment:
        validator_key_usage.append('data_encipherment')
    if ext.key_agreement:
        validator_key_usage.append('key_agreement')
        if ext.decipher_only:
            validator_key_usage.append('decipher_only')
        if ext.encipher_only:
            validator_key_usage.append('encipher_only')
    if ext.key_cert_sign:
        validator_key_usage.append('key_cert_sign')
    if ext.crl_sign:
        validator_key_usage.append('crl_sign')
    return validator_key_usage

def get_ski_aki(cert :Certificate) -> tuple[str, str]:
    ski = None
    aki = None
    for ext in get_certificate_extensions(cert):
        if ext['name'] == 'subjectKeyIdentifier':
            ski = ext[ext['name']]
        if ext['name'] == 'authorityKeyIdentifier':
            aki = ext[ext['name']]

    return ski, aki

def extract_from_subject(cert :Certificate, name :str = 'commonName'):
    for fields in cert.subject:
        current = str(fields.oid)
        if name in current:
            return fields.value
    return None

def validate_common_name(common_name :str, host :str) -> bool:
    if not isinstance(common_name, str):
        raise ValueError("invalid certificate_common_name provided")
    if not isinstance(host, str):
        raise ValueError("invalid host provided")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    if common_name.startswith('*.'):
        common_name_suffix = common_name.replace('*.', '')
        if validators.domain(common_name_suffix) is not True:
            return False
        return common_name_suffix == host or host.endswith(common_name_suffix)
    return validators.domain(common_name) is True

def match_hostname(host :str, cert :Certificate) -> bool:
    if not isinstance(host, str):
        raise ValueError("invalid host provided")
    if not isinstance(cert, Certificate):
        raise ValueError("invalid Certificate provided")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    certificate_san = []
    try:
        certificate_san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except extensions.ExtensionNotFound as ex:
        logger.debug(ex, stack_info=True)
    valid_common_name = False
    wildcard_hosts = set()
    domains = set()
    for fields in cert.subject:
        current = str(fields.oid)
        if "commonName" in current:
            valid_common_name = validate_common_name(fields.value, host)
    for san in certificate_san:
        if san.startswith('*.'):
            wildcard_hosts.add(san)
        else:
            domains.add(san)
    matched_wildcard = False
    for wildcard in wildcard_hosts:
        check = wildcard.replace('*', '')
        if host.endswith(check):
            matched_wildcard = True
            break

    return valid_common_name is True and (matched_wildcard is True or host in domains)

def validate_certificate_chain(der :bytes, pem_certificate_chain :list, validator_key_usage :list, validator_extended_key_usage :list):
    # TODO perhaps remove certvalidator, consider once merged: https://github.com/pyca/cryptography/issues/2381
    ctx = ValidationContext(allow_fetching=True, revocation_mode='hard-fail', weak_hash_algos=set(["md2", "md5", "sha1"]))
    validator = CertificateValidator(der, validation_context=ctx, intermediate_certs=pem_certificate_chain)
    return validator.validate_usage(
        key_usage=set(validator_key_usage),
        extended_key_usage=set(validator_extended_key_usage),
    )

def issuer_from_chain(certificate :X509, chain :list[X509]) -> Certificate:
    issuer = None
    issuer_name = certificate.get_issuer().CN.strip()
    for peer in chain:
        if peer.get_subject().CN.strip() == issuer_name:
            issuer = peer
            break
    return issuer

def str_n_split(input :str, n :int = 2, delimiter :str = ' '):
    if not isinstance(input, str): return input
    return delimiter.join([input[i:i+n] for i in range(0, len(input), n)])

def convert_x509_to_PEM(certificate_chain :list) -> list[bytes]:
    pem_certs = []
    for cert in certificate_chain:
        if not isinstance(cert, X509):
            raise AttributeError(f'convert_x509_to_PEM expected OpenSSL.crypto.X509, got {type(cert)}')
        pem_certs.append(dump_certificate(FILETYPE_PEM, cert))
    return pem_certs

def date_diff(comparer :datetime) -> str:
    interval = comparer - datetime.utcnow()
    if interval.days < -1:
        return f"Expired {int(abs(interval.days))} days ago"
    if interval.days == -1:
        return "Expired yesterday"
    if interval.days == 0:
        return "Expires today"
    if interval.days == 1:
        return "Expires tomorrow"
    if interval.days > 365:
        return f"Expires in {interval.days} days ({int(round(interval.days/365))} years)"
    if interval.days > 1:
        return f"Expires in {interval.days} days"

def styled_boolean(value :bool, represent_as :tuple[str, str] = ('True', 'False'), colors :tuple[str, str] = ('dark_sea_green2', 'light_coral')) -> str:
    console = Console()
    if not isinstance(value, bool):
        raise TypeError(f'{type(value)} provided')
    val = represent_as[0] if value else represent_as[1]
    color = colors[0] if value else colors[1]
    with console.capture() as capture:
        console.print(val, style=Style(color=color))
    return capture.get().strip()

def styled_value(value :str, color :str = 'white', bold :bool = False, crop :bool = True) -> str:
    console = Console()
    with console.capture() as capture:
        console.print(value, style=Style(color=color))
    return capture.get().strip()

def styled_list(values :list, delimiter :str = '\n', color :str = 'bright_white') -> str:
    styled_values = []
    for value in values:
        if value is None:
            styled_values.append(styled_value('Unknown', 'cornflower_blue'))
            continue
        if isinstance(value, bool):
            styled_values.append(styled_boolean(value, colors=(color, color)))
            continue
        if isinstance(value, list):
            styled_values.append(styled_list(value, delimiter, color))
            continue
        if isinstance(value, dict):
            styled_values.append(styled_dict(value, delimiter, colors=(color, color)))
            continue
        if isinstance(value, bytes):
            value = value.decode()
        if isinstance(value, datetime):
            value = value.isoformat()
        styled_values.append(styled_value(str(value), color=color))

    return delimiter.join(styled_values)

def styled_dict(values :dict, delimiter :str = '=', colors :tuple[str, str] = ('bright_white', 'bright_white')) -> str:
    pairs = []
    for key, v in values.items():
        if isinstance(v, bool):
            pairs.append(f'{key}={styled_boolean(v)}')
            continue
        if v is None:
            pairs.append(f'{key}={styled_value("null", color=colors[1])}')
            continue
        if isinstance(v, list):
            pairs.append(f'{key}={styled_list(v, color=colors[1])}')
            continue
        if isinstance(v, dict):
            pairs.append(f'{key}={styled_dict(v, delimiter=delimiter, colors=colors)}')
            continue
        if isinstance(v, (int, float)):
            v = str(v)
        if isinstance(v, bytes):
            v = v.decode()
        if isinstance(v, datetime):
            v = v.isoformat()
        if isinstance(v, str):
            pairs.append(f'{key}{delimiter}{styled_value(v, color=colors[1])}')
    return '\n'.join(pairs)

def styled_any(value, dict_delimiter='=', list_delimiter='\n', color :str = 'bright_white') -> str:
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if isinstance(value, (str, int)):
        return str(value)
    if value is None:
        return styled_value('None', color=color)
    if isinstance(value, bool):
        return styled_boolean(value)
    if isinstance(value, dict):
        return styled_dict(value, delimiter=dict_delimiter)
    if isinstance(value, list):
        return styled_list(value, delimiter=list_delimiter, color=color)
    if isinstance(value, bytes):
        return styled_value(value.decode(), color=color)
    if isinstance(value, datetime):
        return styled_value(value.isoformat(), color=color)
    return styled_value(value, color=color)

def get_dnssec(domain_name :str):
    logger.warning(DeprecationWarning('util.get_dnssec() was deprecated in version 0.4.3 and will be removed in version 0.5.0'), exc_info=True)
    return get_dnssec_answer(domain_name)

def get_dnssec_answer(domain_name :str):
    logger.info(f'Trying to resolve DNSSEC for {domain_name}')
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    tldext = TLDExtract(cache_dir='/tmp')(f'http://{domain_name}')
    answers = []
    try:
        response = resolver.query(domain_name, rdatatype.NS)
    except NoAnswer:
        return get_dnssec_answer(tldext.registered_domain) if tldext.registered_domain != domain_name else None
    except DNSTimeoutError:
        logger.warning('DNS Timeout')
        return None
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
        return None
    except ConnectionResetError:
        logger.warning('Connection reset by peer')
        return None
    except ConnectionError:
        logger.warning('Name or service not known')
        return None
    dns_resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
    nameservers = []
    for ns in [i.to_text() for i in response.rrset]:
        logger.info(f'Checking A for {ns}')
        try:
            response = dns_resolver.query(ns, rdtype=rdatatype.A)
        except DNSTimeoutError:
            logger.warning(f'DNS Timeout {ns} A')
            continue
        except DNSException as ex:
            logger.warning(ex, exc_info=True)
            continue
        except ConnectionResetError:
            logger.warning(f'Connection reset by peer {ns} A')
            continue
        except ConnectionError:
            logger.warning(f'Name or service not known {ns} A')
            continue
        nameservers += [i.to_text() for i in response.rrset]
    if not nameservers:
        logger.warning('No nameservers found')
        return None
    for ns in nameservers:
        logger.info(f'Trying to resolve DNSKEY using NS {ns}')
        try:
            request = message.make_query(domain_name, rdatatype.DNSKEY, want_dnssec=True)
            response = query.udp(request, ns, timeout=2)
        except DNSTimeoutError:
            logger.warning('DNSKEY DNS Timeout')
            continue
        except DNSException as ex:
            logger.warning(ex, exc_info=True)
            continue
        except ConnectionResetError:
            logger.warning('DNSKEY Connection reset by peer')
            continue
        except ConnectionError:
            logger.warning('DNSKEY Name or service not known')
            continue
        if response.rcode() != 0:
            logger.warning('No DNSKEY record')
            continue

        logger.info(f'{ns} answered {response.answer}')
        if len(response.answer) == 2:
            return response.answer
        answers += response.answer
        if len(answers) == 2:
            return answers

    return get_dnssec_answer(tldext.registered_domain) if tldext.registered_domain != domain_name else None

def dnssec_valid(domain_name) -> bool:
    answer = get_dnssec_answer(domain_name)
    if answer is None:
        return False
    if len(answer) != 2:
        logger.warning(f'DNSKEY answer too many values {len(answer)}')
        return False
    name = dns_name.from_text(domain_name)
    try:
        dnssec.validate(answer[0], answer[1], {name: answer[0]})
    except dnssec.ValidationFailure as err:
        logger.warning(err, exc_info=True)
        return False
    return True

def get_caa(domain_name :str):
    tldext = TLDExtract(cache_dir='/tmp')(f'http://{domain_name}')
    try_apex = tldext.registered_domain != domain_name
    response = None
    dns_resolver = resolver.Resolver(configure=False)
    dns_resolver.lifetime = 5
    try:
        response = resolver.query(domain_name, rdatatype.CAA)
    except DNSTimeoutError:
        logger.warning('DNS Timeout')
    except DNSException as ex:
        logger.warning(ex, exc_info=True)
    except ConnectionResetError:
        logger.warning('Connection reset by peer')
    except ConnectionError:
        logger.warning('Name or service not known')
    if not response and try_apex:
        logger.info(f'Trying to resolve CAA for {tldext.registered_domain}')
        return get_caa(tldext.registered_domain)
    if not response:
        return None
    return response

def caa_exist(domain_name :str) -> bool:
    logger.info(f'Trying to resolve CAA for {domain_name}')
    response = get_caa(domain_name)
    if response is None:
        logger.info('No CAA records')
        return False
    issuers = set()
    for rdata in response:
        common_name, *rest = rdata.value.decode().split(';')
        issuers.add(common_name.strip())

    return len(issuers) > 0

def caa_valid(domain_name :str, cert :X509, certificate_chain :list[X509]) -> bool:
    extractor = TLDExtract(cache_dir='/tmp')
    response = get_caa(domain_name)
    if response is None:
        return False
    wild_issuers = set()
    issuers = set()
    for rdata in response:
        caa, *rest = rdata.value.decode().split(';')
        if 'issuewild' in rdata.to_text():
            wild_issuers.add(caa.strip())
    for rdata in response:
        caa, *rest = rdata.value.decode().split(';')
        # issuewild tags take precedence over issue tags when specified.
        if caa not in wild_issuers:
            issuers.add(caa.strip())

    issuer = issuer_from_chain(cert, certificate_chain)
    if not isinstance(issuer, X509):
        logger.warning('Issuer certificate not found in chain')
        return False
    
    common_name = cert.get_subject().CN
    issuer_cn = issuer.get_subject().O
    for caa in wild_issuers:
        issuer_common_names :list[str] = CAA_DOMAINS.get(caa, [])
        if not issuer_common_names:
            issuer_ext = extractor(f'http://{caa}')
            issuer_apex = issuer_ext.registered_domain
            issuer_common_names = CAA_DOMAINS.get(issuer_apex, [])
        if issuer_cn in issuer_common_names:
            return True

    if common_name.startswith('*.'):
        return False

    for caa in issuers:
        issuer_common_names :list[str] = CAA_DOMAINS.get(caa, [])
        if not issuer_common_names:
            issuer_ext = extractor(f'http://{caa}')
            issuer_apex = issuer_ext.registered_domain
            issuer_common_names = CAA_DOMAINS.get(issuer_apex, [])
        if issuer_cn in issuer_common_names:
            return True

    return False

def crlite_revoked(db_path :str, pem :bytes):
    def find_attachments_base_url():
        url = urlparse(CRLITE_URL)
        base_rsp = requests.get(f"{url.scheme}://{url.netloc}/v1/")
        return base_rsp.json()["capabilities"]["attachments"]["base_url"]

    db_dir = Path(db_path)
    if not db_dir.is_dir():
        db_dir.mkdir()

    last_updated = None
    last_updated_file = (db_dir / ".last_updated")
    if last_updated_file.is_file():
        last_updated = datetime.fromtimestamp(last_updated_file.stat().st_mtime)
    grace_time = datetime.utcnow() - timedelta(hours=6)
    update = True
    if last_updated is not None and last_updated > grace_time:
        logger.info(f"Database was updated at {last_updated}, skipping.")
        update = False
    crlite_db = CRLiteDB(db_path=db_path)
    if update:
        crlite_db.update(
            collection_url=CRLITE_URL,
            attachments_base_url=find_attachments_base_url(),
        )
        crlite_db.cleanup()
        last_updated_file.touch()
        logger.info(f"Status: {crlite_db}")
    query = CRLiteQuery(crlite_db=crlite_db, intermediates_db=IntermediatesDB(db_path=db_path, download_pems=False))
    results = []
    for result in query.query(name='peer', generator=query.gen_from_pem(BytesIO(pem))):
        logger.info(result.print_query_result(verbose=1))
        logger.debug(result.print_query_result(verbose=3))
        results.append(result.is_revoked())
    return any(results)
