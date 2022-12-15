from enum import Enum
from typing import Union, Any, Optional
from datetime import datetime

from pydantic import (
    BaseModel,
    Field,
    AnyHttpUrl,
    validator,
    conint,
    PositiveInt,
    PositiveFloat,
    IPvAnyAddress,
)


class OutputType(str, Enum):
    JSON = "json"
    CONSOLE = "console"


class OutputWhen(str, Enum):
    FINAL = "final"
    PER_HOST = "per_host"
    PER_CERTIFICATE = "per_certificate"


class CertificateType(str, Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    LEAF = "leaf"
    CLIENT = "client"


class ValidationLevel(str, Enum):
    DOMAIN_VALIDATION = "Domain Validation (DV)"
    ORGANIZATION_VALIDATION = "Organization Validation (OV)"
    EXTENDED_VALIDATION = "Extended Validation (EV)"


class PublicKeyType(str, Enum):
    RSA = "RSA"
    DSA = "DSA"
    EC = "EC"
    DH = "DH"


class ReportType(str, Enum):
    HOST = "host"
    CERTIFICATE = "certificate"
    REPORT = "report"
    EVALUATIONS = "evaluations"


class DefaultInfo(BaseModel):
    generator: str = Field(default="trivialscan")
    version: Union[str, None] = Field(
        default=None, description="trivialscan CLI version"
    )
    account_name: Union[str, None] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Union[str, None] = Field(
        default=None, description="Machine name where trivialscan CLI execcutes"
    )


class ConfigDefaults(BaseModel):
    use_sni: bool
    cafiles: Union[str, None] = Field(default=None)
    tmp_path_prefix: str = Field(default="/tmp")
    http_path: str = Field(default="/")
    checkpoint: Optional[bool]


class ConfigOutput(BaseModel):
    type: OutputType
    use_icons: Union[bool, None]
    when: OutputWhen = Field(default=OutputWhen.FINAL)
    path: Union[str, None] = Field(default=None)


class ConfigTarget(BaseModel):
    hostname: str
    port: PositiveInt = Field(default=443)
    client_certificate: Union[str, None] = Field(default=None)
    http_request_paths: list[str] = Field(default=["/"])


class Config(BaseModel):
    account_name: Union[str, None] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Union[str, None] = Field(
        default=None, description="Machine name where trivialscan CLI execcutes"
    )
    project_name: Union[str, None] = Field(
        default=None, description="Trivial Scanner project assignment for the report"
    )
    defaults: ConfigDefaults
    outputs: list[ConfigOutput]
    targets: list[ConfigTarget]


class Flags(BaseModel):
    hide_progress_bars: Optional[bool]
    synchronous_only: Optional[bool]
    hide_banner: Optional[bool]
    track_changes: Optional[bool]
    previous_report: Union[str, None]
    quiet: Optional[bool]


class HostTLSProtocol(BaseModel):
    negotiated: str
    preferred: str
    offered: list[str]


class HostTLSCipher(BaseModel):
    forward_anonymity: Union[bool, None] = Field(default=False)
    offered: list[str]
    offered_rfc: list[str]
    negotiated: str
    negotiated_bits: PositiveInt
    negotiated_rfc: str


class HostTLSClient(BaseModel):
    certificate_mtls_expected: Union[bool, None] = Field(default=False)
    certificate_trusted: Union[bool, None] = Field(default=False)
    certificate_match: Union[bool, None] = Field(default=False)
    expected_client_subjects: list[str] = Field(default=[])


class HostTLSSessionResumption(BaseModel):
    cache_mode: str
    tickets: bool
    ticket_hint: bool


class HostTLS(BaseModel):
    certificates: list[str] = Field(default=[])
    client: HostTLSClient
    cipher: HostTLSCipher
    protocol: HostTLSProtocol
    session_resumption: HostTLSSessionResumption


class HostHTTP(BaseModel):
    title: str
    status_code: conint(ge=100, le=599)  # type: ignore
    headers: dict[str, str]
    body_hash: str


class HostTransport(BaseModel):
    error: Optional[tuple[str, str]]
    hostname: str = Field(title="Domain Name")
    port: PositiveInt = Field(default=443)
    sni_support: Optional[bool]
    peer_address: Optional[IPvAnyAddress]
    certificate_mtls_expected: Union[bool, None] = Field(default=False)


class Host(BaseModel):
    last_updated: Optional[datetime]
    transport: HostTransport
    tls: Optional[HostTLS]
    http: Optional[list[HostHTTP]]
    scanning_status: Union[dict[str, Any], None] = Field(default=None)


class Certificate(BaseModel):
    authority_key_identifier: Union[str, None] = Field(default=None)
    expired: Optional[bool]
    expiry_status: Optional[str]
    extensions: Optional[list] = Field(default=[])
    external_refs: Optional[dict[str, Union[AnyHttpUrl, None]]] = Field(default={})
    is_self_signed: Optional[bool]
    issuer: Optional[str]
    known_compromised: Optional[bool]
    md5_fingerprint: Optional[str]
    not_after: Optional[datetime]
    not_before: Optional[datetime]
    public_key_curve: Union[str, None] = Field(default=None)
    public_key_exponent: Union[PositiveInt, None] = Field(default=None)
    public_key_modulus: Union[PositiveInt, None] = Field(default=None)
    public_key_size: Optional[PositiveInt]
    public_key_type: Optional[PublicKeyType]
    revocation_crl_urls: Optional[list[AnyHttpUrl]] = Field(default=[])
    san: Optional[list[str]] = Field(default=[])
    serial_number: Optional[str]
    serial_number_decimal: Optional[Any]
    serial_number_hex: Optional[str]
    sha1_fingerprint: str
    sha256_fingerprint: Optional[str]
    signature_algorithm: Optional[str]
    spki_fingerprint: Optional[str]
    subject: Optional[str]
    subject_key_identifier: Optional[str]
    validation_level: Union[ValidationLevel, None] = Field(default=None)
    validation_oid: Union[str, None] = Field(default=None)
    version: Optional[Any] = Field(default=None)
    type: Optional[CertificateType]


class ComplianceItem(BaseModel):
    requirement: Union[str, None] = Field(default=None)
    title: Union[str, None] = Field(default=None)
    description: Union[str, None] = Field(default=None)


class ComplianceName(str, Enum):
    PCI_DSS = "PCI DSS"
    NIST_SP800_131A = "NIST SP800-131A"
    FIPS_140_2 = "FIPS 140-2"


class ComplianceGroup(BaseModel):
    compliance: Optional[ComplianceName]
    version: Optional[str]
    items: Union[list[ComplianceItem], None] = Field(default=[])


class ThreatItem(BaseModel):
    standard: str
    version: str
    tactic: Union[str, None] = Field(default=None)
    tactic_id: Union[str, None] = Field(default=None)
    tactic_url: Union[AnyHttpUrl, None] = Field(default=None)
    tactic_description: Union[str, None] = Field(default=None)
    technique: Union[str, None] = Field(default=None)
    technique_id: Union[str, None] = Field(default=None)
    technique_url: Union[AnyHttpUrl, None] = Field(default=None)
    technique_description: Union[str, None] = Field(default=None)
    mitigation: Union[str, None] = Field(default=None)
    mitigation_id: Union[str, None] = Field(default=None)
    mitigation_url: Union[AnyHttpUrl, None] = Field(default=None)
    mitigation_description: Union[str, None] = Field(default=None)
    sub_technique: Union[str, None] = Field(default=None)
    sub_technique_id: Union[str, None] = Field(default=None)
    sub_technique_url: Union[AnyHttpUrl, None] = Field(default=None)
    sub_technique_description: Union[str, None] = Field(default=None)
    data_source: Union[str, None] = Field(default=None)
    data_source_id: Union[str, None] = Field(default=None)
    data_source_url: Union[AnyHttpUrl, None] = Field(default=None)
    data_source_description: Union[str, None] = Field(default=None)


class ReferenceType(str, Enum):
    WEBSITE = "website"
    JSON = "json"


class ReferenceItem(BaseModel):
    name: str
    url: AnyHttpUrl
    type: Optional[ReferenceType] = Field(default=ReferenceType.WEBSITE)


class ScanRecordType(str, Enum):
    MONITORING = "Managed Monitoring"
    ONDEMAND = "Managed On-demand"
    SELF_MANAGED = "Customer-managed"


class ScanRecordCategory(str, Enum):
    ASM = "Attack Surface Monitoring"
    RECONNAISSANCE = "Reconnaissance"
    OSINT = "Public Data Sources"
    INTEGRATION_DATA = "Third Party Integration"


class ReportSummary(DefaultInfo):
    report_id: Optional[str]
    project_name: Union[str, None]
    targets: Optional[list[Host]] = Field(default=[])
    date: Optional[datetime]
    execution_duration_seconds: Union[PositiveFloat, None] = Field(default=None)
    score: int = Field(default=0)
    results: Optional[dict[str, int]]
    certificates: Optional[list[Certificate]] = Field(default=[])
    results_uri: Optional[str]
    flags: Union[Flags, None] = Field(default=None)
    config: Union[Config, None] = Field(default=None)


class EvaluationItem(DefaultInfo):
    class Config:
        validate_assignment = True

    report_id: str
    rule_id: int
    group_id: int
    key: str
    name: str
    group: str
    observed_at: Union[datetime, None] = Field(default=None)
    result_value: Union[bool, str, None]
    result_label: str
    result_text: str
    result_level: Union[str, None] = Field(default=None)
    score: int = Field(default=0)
    metadata: dict[str, Any] = Field(default={})
    cve: Union[list[str], None] = Field(default=[])
    cvss2: Union[str, Any] = Field(default=None)
    cvss3: Union[str, Any] = Field(default=None)
    references: Union[list[ReferenceItem], None] = Field(default=[])
    compliance: Union[list[ComplianceGroup], None] = Field(default=[])
    threats: Union[list[ThreatItem], None] = Field(default=[])
    transport: Optional[HostTransport]
    certificate: Optional[Certificate]

    @validator("references")
    def set_references(cls, references):
        return [] if not isinstance(references, list) else references

    @validator("cvss2")
    def set_cvss2(cls, cvss2):
        return None if not isinstance(cvss2, str) else cvss2

    @validator("cvss3")
    def set_cvss3(cls, cvss3):
        return None if not isinstance(cvss3, str) else cvss3


class FullReport(ReportSummary):
    evaluations: Optional[list[EvaluationItem]] = Field(default=[])
