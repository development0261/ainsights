import datetime
import re
import typing


class _SSLCertResult(typing.TypedDict):
    subject: str
    subject_alternative_name: str
    issuer: str
    public_key_type: str
    public_key_bits: str
    signature_algorithm: str
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    md5: str
    sha_1: str


class _HttpSecurityHeadersResult(typing.TypedDict):
    header: str
    value: str
    description: str


def parse_ssl_cert(contents: str) -> _SSLCertResult:

    result = _SSLCertResult()
    ssl_cert_regex = re.compile("([a-z0-9-]+[a-z0-9- ]+): (.*)", re.IGNORECASE)

    for key, val in ssl_cert_regex.findall(contents):
        result[key.strip().lower().replace(" ", "_").replace("-", "_")] = val.strip()

    return result


def parse_ssl_enum_ciphers(contents: str) -> dict:
    return {}


def parse_http_security_headers(
    contents: str,
) -> typing.List[_HttpSecurityHeadersResult]:

    results = []
    regex = re.compile("header: (.+): (.*)(\n? *description: (.*))?", re.IGNORECASE)

    for header, val, _, desc in regex.findall(contents):
        results.append(
            _HttpSecurityHeadersResult(
                header=header.strip(),
                value=val.strip(),
                description=desc.strip(),
            )
        )

    return results
