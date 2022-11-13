# Compromised Certificates

Not all compromised certificates are necessary to be noted by `trivialscan` because they may already appear in CRLite or be revoked via OCSP, therefore many known compromised certificates will not be reported as 'compromised' using `trivialscan` (they will show as revoked though).

## Research

Various compromises investigated and the result

### Certinomis 2018

Lesser known issue in 2018 resulted in removal of the Root CA issuer entirely

Results:

- our use of `tlstrust` will uncover these via CCADB

### GoDaddy 2014-2018

Captured [in bugzilla](https://wiki.mozilla.org/CA/Responding_To_An_Incident#Incident_Report) and effected 865 certificates; all are showing as revoked in crt.sh via CRL/OCSP

### Symantec 2017

The [Symantec](https://groups.google.com/a/chromium.org/g/blink-dev/c/eUAKwjihhBs/m/El1mH8S6AwAJ) trust issue included 2k certificates that were not associated with registered domains, therefore many were not considered a risk to the browsers! Even though each of them are capable of being used maliciously, they simply can't be a server 'leaf' Certificate, so for the purposes of `trivialscan` we will need to distrust any that appear in a certificate chain.

Results:

- Appear as a Root CA; Root stores have all revoked the Symantec so our use of `tlstrust` will uncover these
- Appear as a peer/intermediate; CRLite will report these as revoked, which leveraged OneCRL for intermediate certificates
- Appear as a 'leaf' DigiCert's acquisition of Symantec required these to be revoked, so CRLite will report these via the CRL/OCSP

### Comodo 2016

There were some certs issued to the wrong people due to a bug in the OCR process, all were revoked and are showing in cert.sh

Also in 2016 a [researcher](https://thehackerblog.com/keeping-positive-obtaining-arbitrary-wildcard-ssl-certificates-from-comodo-via-dangling-markup-injection/index.html) found that you can request any wildcard cert from Comodo, no known compromises reported (or found)

### StartCom 2016
