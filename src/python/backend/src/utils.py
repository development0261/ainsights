import re


def is_valid_email(email: str) -> bool:
    raise NotImplementedError


def is_valid_domain(domain: str) -> bool:

    domain_regex = re.compile(
        r"^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|"
        r"([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|"
        r"([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\."
        r"([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$"
    )

    return True if domain_regex.match(domain) is not None else False


def is_valid_ipv4(ipv4_addrs: str) -> bool:

    # remove whitespace from ipv4_addrs
    ipv4_addrs = ipv4_addrs.strip()

    # if a single ipv4 address is provided
    single_ipv4_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if single_ipv4_regex.match(ipv4_addrs):
        return True

    # if cidr notation is used
    cidr_ipv4_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
    if cidr_ipv4_regex.match(ipv4_addrs) and int(ipv4_addrs.split("/")[-1]) <= 32:
        return True

    # if dash separated ipv4 addresses are provided
    dash_sep_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d+$")
    if dash_sep_regex.match(ipv4_addrs):
        return True

    # if space separated ipv4 addresses are provided
    space_sep_regex = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"( *\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})*$"
    )
    if space_sep_regex.match(ipv4_addrs):
        return True

    return False


def is_valid_port(ports: str) -> bool:

    # remove whitespace from ports
    ports = ports.strip()

    # if a single port is provided
    single_port_regex = re.compile(r"^\d{1,5}$")
    if single_port_regex.match(ports) is not None:
        return True

    # if comma separated ports are provided
    comma_sep_regex = re.compile(r"^\d{1,5}( *, *\d{1,5})*$")
    if comma_sep_regex.match(ports) is not None:
        return True

    # if dash separated ports are provided
    dash_sep_regex = re.compile(r"^\d{1,5}-\d{1,5}$")
    if dash_sep_regex.match(ports) is not None:
        return True

    # all other port formats are invalid
    return False


def count_ports(ports: str) -> int:

    # remove whitespace from ports
    ports = ports.strip()

    # if a single port is provided
    single_port_regex = re.compile(r"^\d{1,5}$")
    if single_port_regex.match(ports) is not None:
        return 1

    # if comma separated ports are provided
    comma_sep_regex = re.compile(r"^\d{1,5}( *, *\d{1,5})*$")
    if comma_sep_regex.match(ports) is not None:
        return len(ports.split(","))

    # if dash separated ports are provided
    dash_sep_regex = re.compile(r"^\d{1,5}-\d{1,5}$")
    if dash_sep_regex.match(ports) is not None:
        start, end = ports.split("-")
        return int(end) - int(start) + 1

    # all other port formats are invalid
    return 0


def count_ipv4(ipv4_addrs: str) -> int:

    # remove whitespace from ipv4_addrs
    ipv4_addrs = ipv4_addrs.strip()

    # if a single ipv4 address is provided
    single_ipv4_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if single_ipv4_regex.match(ipv4_addrs):
        return 1

    # if cidr notation is used
    cidr_ipv4_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
    if cidr_ipv4_regex.match(ipv4_addrs):
        return 2 ** (32 - int(ipv4_addrs.split("/")[-1]))

    # if dash separated ipv4 addresses are provided
    dash_sep_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d+$")
    if dash_sep_regex.match(ipv4_addrs):
        return int(ipv4_addrs.split("-")[-1])

    # if space separated ipv4 addresses are provided
    space_sep_regex = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"( *\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})*$"
    )
    if space_sep_regex.match(ipv4_addrs):
        return len(re.split(r"\s+", ipv4_addrs))

    return 0
