from typing import List

from pydantic import BaseModel


class AuthResponse(BaseModel):
    email: str
    user_id: str
    is_admin: bool
    access_token: str


class DomainScanResponse(BaseModel):
    query_type: str
    records: List[str] = []


class PortResponse(BaseModel):
    port: str
    state: str
    protocol: str


class PortScanResponse(BaseModel):

    host: str
    state: str
    ports: List[PortResponse] = []


class SSLScanResponse(BaseModel):
    host: str
    certs: str
    ciphers: str
