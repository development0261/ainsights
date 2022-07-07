from dataclasses import dataclass

from pydantic import BaseModel

from . import exc
from . import utils


@dataclass
class UserOnboardingRequest:
    domain: str
    ports: str
    ipv4_addrs: str
    schedule : str

    def __post_init__(self) -> None:

        if utils.is_valid_domain(self.domain) is False:
            raise exc.ValidationException("invalid domain name")

        if utils.is_valid_ipv4(self.ipv4_addrs) is False:
            raise exc.ValidationException("invalid ipv4 address(s)")

        if utils.is_valid_port(self.ports) is False:
            raise exc.ValidationException("invalid port(s)")

        if self.ports == "0":
            self.ports == ""


class DomainScanRequest(BaseModel):
    domain: str

    def __post_init__(self) -> None:

        if utils.is_valid_domain(self.domain) is False:
            raise exc.ValidationException("invalid domain name")


@dataclass
class SyncPortScanRequest:
    ipv4_addrs: str
    ports: str

    def __post_init__(self) -> None:

        if utils.is_valid_ipv4(self.ipv4_addrs) is False:
            raise exc.ValidationException("invalid ipv4 address(s)")

        if utils.count_ipv4(self.ipv4_addrs) > 3:
            raise exc.ValidationException("max of 3 ipv4 address(s) should be provided")

        if utils.is_valid_port(self.ports) is False:
            raise exc.ValidationException("invalid port(s)")

        if utils.count_ports(self.ports) > 3 or self.ports == "0" or self.ports == "":
            raise exc.ValidationException("max of 3 port(s) should be provided")


@dataclass
class AsyncPortScanRequest:
    ipv4_addrs: str
    ports: str

    def __post_init__(self) -> None:

        if utils.is_valid_ipv4(self.ipv4_addrs) is False:
            raise exc.ValidationException("invalid ipv4 address(s)")

        if utils.is_valid_port(self.ports) is False:
            raise exc.ValidationException("invalid port(s)")

        if self.ports == "0":
            self.ports == ""


class AuthRequest(BaseModel):
    email: str
    password: str


@dataclass
class DomainRegistrationRequest:
    domain: str

    def __post_init__(self) -> None:

        if utils.is_valid_domain(self.domain) is False:
            raise exc.ValidationException("invalid domain")


@dataclass
class Ipv4RegistrationRequest:
    ipv4_addrs: str
    ports: str

    def __post_init__(self) -> None:

        if utils.is_valid_ipv4(self.ipv4_addrs) is False:
            raise exc.ValidationException("invalid ipv4 address(s)")

        if utils.is_valid_port(self.ports) is False:
            raise exc.ValidationException("invalid port(s)")

        if self.ports == "0":
            self.ports = ""
