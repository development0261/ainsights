from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class User(BaseModel):
    id_: str
    email: str
    is_admin: bool

    @classmethod
    def from_db_row(cls, row) -> User:
        return cls(id_=row[0], email=row[1], is_admin=row[2])


class AuthUser(User):
    hashed_password: str

    @classmethod
    def from_db_row(cls, row) -> AuthUser:
        return cls(id_=row[0], email=row[1], is_admin=row[2], hashed_password=row[3])


class UserDomain(BaseModel):
    id_: str
    user_id: str
    domain: str
    created_at: datetime = datetime.now()
    updated_at: datetime = datetime.now()
    schedule: bool

    @classmethod
    def from_db_row(cls, row) -> UserDomain:
        return cls(
            id_=row[0],
            user_id=row[1],
            domain=row[2],
            created_at=row[3],
            updated_at=row[4],
            schedule=row[5],
        )


class UserIP(BaseModel):
    id_: str
    user_id: str
    ipv4_addrs: str
    ports: str
    created_at: datetime = datetime.now()
    updated_at: datetime = datetime.now()

    @classmethod
    def from_db_row(cls, row) -> UserIP:
        return cls(
            id_=row[0],
            user_id=row[1],
            ipv4_addrs=row[2],
            ports=row[3],
            created_at=row[4],
            updated_at=row[5],
        )


class DomainScanResult(BaseModel):
    id_: str
    scan_id: str
    record_type: str
    record_values: str

    @classmethod
    def from_db_row(cls, row) -> DomainScanResult:
        return cls(id_=row[0], scan_id=row[1], record_type=row[2], record_values=row[3])


class ScanState(Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Scan(BaseModel):
    id_: str
    state: ScanState
    user_domain_id: str | None
    user_port_id: str | None
    domain: str | None
    ipv4_addrs: str | None
    ports: str | None
    source_ipv4_addr: str | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_db_row(cls, row) -> Scan:

        return cls(
            id_=row[0],
            user_domain_id=row[1],
            user_port_id=row[2],
            domain=row[3],
            ipv4_addrs=row[4],
            ports=row[5],
            source_ipv4_addr=row[6],
            state=row[7],
            created_at=row[8],
            updated_at=row[9],
        )


class SSLCertResult(BaseModel):
    id_: str
    scan_result_id: str
    subject: str
    subject_alternative_name: str
    issuer: str
    public_key_type: str
    public_key_bits: str
    signature_algorithm: str
    not_valid_before: datetime
    not_valid_after: datetime
    md5: str
    sha_1: str

    @classmethod
    def from_db_row(cls, row) -> SSLCertResult:
        return cls(
            id_=row[0],
            scan_result_id=row[1],
            subject=row[2],
            subject_alternative_name=row[3],
            issuer=row[4],
            public_key_type=row[5],
            public_key_bits=row[6],
            signature_algorithm=row[7],
            not_valid_before=row[8],
            not_valid_after=row[9],
            md5=row[10],
            sha_1=row[11],
        )


class HttpSecurityHeadersResult(BaseModel):
    id_: str
    scan_result_id: str
    header: str
    value: str
    description: str

    @classmethod
    def from_db_row(cls, row) -> HttpSecurityHeadersResult:
        return cls(
            id_=row[0],
            scan_result_id=row[1],
            header=row[2],
            value=row[3],
            description=row[4],
        )


class PortScanResult(BaseModel):
    id_: str
    scan_id: str
    host: str
    host_state: str
    port: str
    port_state: str
    protocol: str

    ssl_cert: SSLCertResult | None = None
    http_security_headers: List[HttpSecurityHeadersResult] = Field(default_factory=list)

    @classmethod
    def from_db_row(cls, row) -> PortScanResult:
        return cls(
            id_=row[0],
            scan_id=row[1],
            host=row[2],
            host_state=row[3],
            port=row[4],
            port_state=row[5],
            protocol=row[6],
        )
