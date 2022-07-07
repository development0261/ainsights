import re
import subprocess  # nosec
import uuid

import nmap
from . import parsers
import pydig
from multipledispatch import dispatch

from . import db
from . import models


# scan ran by registered user for unregistered domain
@dispatch(str, models.User, str)
def scan_domain(domain: str, user: models.User, kind: str) -> str:

    scan_id = db.start_scan(domain, user)
    _scan_domain(domain=domain, scan_id=scan_id, kind=kind)
    return scan_id


# scan ran by unregistered user for unregistered domain
@dispatch(str, str, str)
def scan_domain(domain: str, source_ipv4_addr: str, kind: str) -> str:

    scan_id = db.start_scan(domain, source_ipv4_addr)
    _scan_domain(domain=domain, scan_id=scan_id, kind=kind)
    return scan_id


# scan ran by registered user for registered domain
@dispatch(models.UserDomain, str)
def scan_domain(domain: models.UserDomain, kind: str) -> str:

    scan_id = db.start_scan(domain)
    _scan_domain(domain=domain.domain, scan_id=scan_id, kind=kind)
    return scan_id


# scan ran by registered user for unregistered ipv4 addresses and ports
@dispatch(str, str, models.User)
def scan_port(ipv4_addrs: str, ports: str, user: models.User) -> str:

    scan_id = db.start_scan(ipv4_addrs, ports, user)
    _scan_port(ipv4_addrs=ipv4_addrs, ports=ports, scan_id=scan_id)
    return scan_id


# scan ran by unregistered user for unregistered ipv4 addresses and ports
@dispatch(str, str, str)
def scan_port(ipv4_addrs: str, ports: str, source_ipv4_addr: str) -> str:

    scan_id = db.start_scan(ipv4_addrs, ports, source_ipv4_addr)
    _scan_port(ipv4_addrs=ipv4_addrs, ports=ports, scan_id=scan_id)
    return scan_id


# scan ran by registered user for registered ipv4 addresses and ports
@dispatch(models.UserIP)
def scan_port(user_ip: models.UserIP) -> str:

    scan_id = db.start_scan(user_ip)
    _scan_port(ipv4_addrs=user_ip.ipv4_addrs, ports=user_ip.ports, scan_id=scan_id)
    return scan_id


# base scan domain handler
def _scan_domain(domain: str, scan_id: str, kind: str) -> None:

    if kind == "dns":
        _scan_dns(domain=domain, scan_id=scan_id)
    elif kind == "ssl":
        _scan_ssl(domain=domain, scan_id=scan_id)
    elif kind == "http":
        _scan_http(domain=domain, scan_id=scan_id)


def _scan_dns(domain: str, scan_id: str) -> None:

    results = {}
    for record_type in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR"]:

        try:
            results[record_type] = pydig.query(domain, record_type)
        except subprocess.CalledProcessError:
            results[record_type] = []

    for record_value in results["TXT"]:

        if record_value.startswith('"v=spf1'):
            results.setdefault("SPF", []).append(record_value)

        if record_value.startswith('"v=DMARC1'):
            results.setdefault("DMARC", []).append(record_value)

        if not record_value.startswith('"v=spf1') and re.match(
            '^".+(=|:).+$', record_value
        ):
            results.setdefault("apps", []).append(record_value)

    db.store_domain_scan_results(scan_id=scan_id, results=results)
    db.finish_scan(scan_id=scan_id)


def _scan_port(ipv4_addrs: str, ports: str, scan_id: str) -> int:

    results = []
    scanner = nmap.PortScanner()
    arguments = "-Pn -PY"

    if ports == "":
        scanner.scan(ipv4_addrs, arguments=arguments)
    else:
        scanner.scan(ipv4_addrs, ports, arguments)

    results = []
    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            lport = scanner[host][protocol].keys()
            for port in sorted(lport):
                results.append(
                    {
                        "id": str(uuid.uuid4()),
                        "scan_id": scan_id,
                        "host": host,
                        "host_state": scanner[host].state(),
                        "port": port,
                        "port_state": scanner[host][protocol][port]["state"],
                        "protocol": protocol,
                    }
                )

    db.store_port_scan_results(results=results)
    db.finish_scan(scan_id=scan_id)

    return scan_id


def _scan_ssl(domain: str, scan_id: str) -> None:

    results = []
    ssl_cert_results = []
    ssl_enum_ciphers_results = []

    port = "443"
    args = "-Pn -PY --script ssl-cert --script ssl-enum-ciphers"
    scanner = nmap.PortScanner()
    scanner.scan(domain, port, args)

    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            lport = scanner[host][protocol].keys()
            for port in sorted(lport):

                result = {
                    "id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "host": host,
                    "host_state": scanner[host].state(),
                    "port": port,
                    "port_state": scanner[host][protocol][port]["state"],
                    "protocol": protocol,
                }

                ssl_cert_result = parsers.parse_ssl_cert(
                    scanner[host][protocol][port].get("script", {}).get("ssl-cert", "")
                )

                if len(ssl_cert_result.keys()):
                    ssl_cert_result["scan_result_id"] = result["id"]
                    ssl_cert_results.append(ssl_cert_result)

                ssl_enum_ciphers_result = parsers.parse_ssl_enum_ciphers(
                    scanner[host][protocol][port]
                    .get("script", {})
                    .get("ssl-enum-ciphers", "")
                )

                if len(ssl_enum_ciphers_result.keys()):
                    ssl_enum_ciphers_result["scan_result_id"] = result["id"]
                    ssl_enum_ciphers_results.append(ssl_enum_ciphers_result)

                results.append(result)

    db.store_port_scan_results(results=results)
    db.store_ssl_cert_results(results=ssl_cert_results)

    db.finish_scan(scan_id=scan_id)


def _scan_http(domain: str, scan_id: str) -> None:

    results = []
    http_security_headers_results = []

    ports = "80,443"
    args = "-Pn -PY --script http-security-headers"
    scanner = nmap.PortScanner()
    scanner.scan(domain, ports, args)

    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            lport = scanner[host][protocol].keys()
            for port in sorted(lport):
                result = {
                    "id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "host": host,
                    "host_state": scanner[host].state(),
                    "port": port,
                    "port_state": scanner[host][protocol][port]["state"],
                    "protocol": protocol,
                }

                _http_security_headers_results = parsers.parse_http_security_headers(
                    scanner[host][protocol][port]
                    .get("script", {})
                    .get("http-security-headers", "")
                )

                for http_security_headers_result in _http_security_headers_results:
                    http_security_headers_result["scan_result_id"] = result["id"]
                    http_security_headers_results.append(http_security_headers_result)

                results.append(result)

    db.store_port_scan_results(results=results)
    db.store_http_security_headers_results(results=http_security_headers_results)
    db.finish_scan(scan_id=scan_id)
