import json
import uuid
from os import environ
from typing import Dict, List

from fastapi import HTTPException
from multipledispatch import dispatch
from psycopg2.errors import UniqueViolation
from psycopg2.pool import ThreadedConnectionPool

from . import exc
from . import models

pool = ThreadedConnectionPool(
    minconn=1,
    maxconn=3,
    # dsn=environ["DATABASE_URL"],
    dsn='postgresql://ainsights:ainsights@localhost/ainsights',
)


def get_auth_user_by_email(email: str) -> models.AuthUser | None:
    sql = "select id, email, is_admin, password from auth.users where email=%s"
    user_row = None

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (email,))
        user_row = cursor.fetchone()
    pool.putconn(connection)

    return models.AuthUser.from_db_row(user_row) if user_row else None


def get_optional_user_by_id(id_: str) -> models.User | None:
    sql = "select id, email, is_admin from auth.users where id=%s"
    user_row = None

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        user_row = cursor.fetchone()
    pool.putconn(connection)

    return models.User.from_db_row(user_row) if user_row is not None else None


def get_optional_user_by_email(email: str) -> models.User | None:
    sql = "select id, email, is_admin from auth.users where email=%s"
    user_row = None

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (email,))
        user_row = cursor.fetchone()
    pool.putconn(connection)

    return models.User.from_db_row(user_row) if user_row is not None else None


def get_user_by_id(id_: str) -> models.User:

    user = get_optional_user_by_id(id_=id_)
    if user is None:
        raise exc.EntityNotFound(f"User(id={id_}) not found")

    return user

# def update_schedule(id_: str, schedule: str) -> models.User:
#     sql = "update auth.users SET schedule=%s WHERE id=%s"
#     print(schedule)

#     user = get_optional_user_by_id(id_=id_)
#     if user is None:
#         raise exc.EntityNotFound(f"User(id={id_}) not found")
    
#     connection = pool.getconn()
#     with connection.cursor() as cursor:
#         print(schedule.replace("'", "\""))
#         cursor.execute(sql, [ .replace("'", "\""), id_])
#         # user_row = cursor.fetchone()
#         connection.commit()
#     pool.putconn(connection)

#     return user


def get_users() -> List[models.User]:
    sql = "select id, email, is_admin from auth.users"
    user_rows = []

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql)
        user_rows = cursor.fetchall()
    pool.putconn(connection)

    return [models.User.from_db_row(row) for row in user_rows]


def get_user_by_email(email: str) -> models.User:

    user = get_optional_user_by_email(email=email)
    if user is None:
        raise exc.EntityNotFound(f"User(email={email}) not found")

    return user


def create_user(email: str, password: str, is_admin: bool = False) -> models.User:

    sql = """insert into auth.users
        (email, password, is_admin) values (%s, %s, %s)"""

    connection = pool.getconn()
    with connection.cursor() as cursor:
        try:
            cursor.execute(sql, (email, password, is_admin))
        except UniqueViolation as err:
            raise HTTPException(status_code=409, detail="User already exists") from err

        connection.commit()
    pool.putconn(connection)

    return get_user_by_email(email=email)


def get_user_domains(id_: str) -> List[models.UserDomain]:
    sql = "select id, user_id, domain, created_at, updated_at, schedule from user_domains where user_id=%s"
    user_domain_rows = []

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        user_domain_rows = cursor.fetchall()
    pool.putconn(connection)

    return [models.UserDomain.from_db_row(row) for row in user_domain_rows]


def get_domain_scans(id_: str) -> List[models.Scan]:
    sql = """
        select
            id, user_domain_id, user_port_id, domain, ipv4_addrs,
            ports, source_ipv4_addr, state, created_at, updated_at
        from scans
            where user_domain_id=%s;
        """
    scan_rows = []

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        scan_rows = cursor.fetchall()
    pool.putconn(connection)

    return [models.Scan.from_db_row(row) for row in scan_rows]


def get_port_scans(id_: str) -> List[models.Scan]:
    sql = """
        select
            id, user_domain_id, user_port_id, domain, ipv4_addrs,
            ports, source_ipv4_addr, state, created_at, updated_at
        from scans
            where user_port_id=%s;
        """
    scan_rows = []

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        scan_rows = cursor.fetchall()
    pool.putconn(connection)

    return [models.Scan.from_db_row(row) for row in scan_rows]


def get_scan_results(
    id_: str,
) -> List[models.DomainScanResult] | List[models.PortScanResult]:

    domain_scan_results = get_domain_scan_results(id_)
    if len(domain_scan_results) > 0:
        return domain_scan_results

    port_scan_results = get_port_scan_results(id_)
    if len(port_scan_results) > 0:
        return port_scan_results

    raise exc.EntityNotFound()


def get_domain_scan_results(id_: str) -> List[models.DomainScanResult]:
    sql = """
        select
            id, scan_id, record_type, record_values
        from domain_scan_results
            where scan_id=%s;
        """
    scan_rows = []

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        scan_rows = cursor.fetchall()
    pool.putconn(connection)

    return [models.DomainScanResult.from_db_row(row) for row in scan_rows]


def get_port_scan_results(id_: str) -> List[models.PortScanResult]:
    sql = """
        select
            id, scan_id, host, host_state, port, port_state, protocol
        from port_scan_results
            where scan_id=%s;
        """
    scan_rows = []

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        scan_rows = cursor.fetchall()
    pool.putconn(connection)

    results = [models.PortScanResult.from_db_row(row) for row in scan_rows]

    for result in results:
        result.ssl_cert = get_ssl_cert_results(id_=result.id_)
        result.http_security_headers = get_http_security_headers_results(id_=result.id_)

    return results


def get_ssl_cert_results(id_: str) -> models.SSLCertResult | None:
    sql = """
        select
            id, scan_result_id, subject, subject_alternative_name,
            issuer, public_key_type, public_key_bits, signature_algorithm,
            not_valid_before, not_valid_after, md5, sha_1
        from ssl_cert_results
            where scan_result_id=%s;
        """
    ssl_cert_result_row = None

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        ssl_cert_result_row = cursor.fetchone()
    pool.putconn(connection)

    return (
        models.SSLCertResult.from_db_row(ssl_cert_result_row)
        if ssl_cert_result_row is not None
        else None
    )


def get_http_security_headers_results(
    id_: str,
) -> List[models.HttpSecurityHeadersResult]:
    sql = """
        select
            id, scan_result_id, header, value, description
        from http_security_headers_results
            where scan_result_id=%s;
        """
    http_security_headers_result_rows = []

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        http_security_headers_result_rows = cursor.fetchall()
    pool.putconn(connection)

    return [
        models.HttpSecurityHeadersResult.from_db_row(row)
        for row in http_security_headers_result_rows
    ]


def get_user_ips(id_: str) -> List[models.UserIP]:
    sql = """
    select
        id, user_id, ipv4_addrs, ports, created_at, updated_at
    from
        user_ports where user_id=%s
    """
    user_ip_rows = []

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(sql, (id_,))
        user_ip_rows = cursor.fetchall()
    pool.putconn(connection)

    return [models.UserIP.from_db_row(row) for row in user_ip_rows]


def store_user(email: str, hashed_password: str) -> None:

    sql = "insert into auth.users (email, password) values (%s, %s, %s)"

    connection = pool.getconn()
    with connection.cursor() as cursor:
        try:
            cursor.execute(sql, (email, hashed_password))
        except UniqueViolation as err:
            pool.putconn(connection)
            raise HTTPException(status_code=409, detail="User already exists") from err
        connection.commit()
    pool.putconn(connection)
    return None


def store_user_domain_registration(user_domain: models.UserDomain) -> None:

    connection = pool.getconn()
    with connection.cursor() as cursor:
        try:
            cursor.execute(
                """
                insert into user_domains
                    (id, user_id, domain, schedule) values (%s, %s, %s, %s);
                """,
                (user_domain.id_, user_domain.user_id, user_domain.domain, user_domain.schedule),
            )
        except UniqueViolation as error:
            pool.putconn(connection)
            raise HTTPException(
                status_code=409, detail="Domain already registered"
            ) from error

        connection.commit()
    pool.putconn(connection)


def store_user_ipv4_registration(user_ip: models.UserIP) -> None:

    connection = pool.getconn()
    with connection.cursor() as cursor:
        try:
            cursor.execute(
                """
                insert into user_ports
                    (id, user_id, ipv4_addrs, ports) values (%s, %s, %s, %s);
                """,
                (user_ip.id_, user_ip.user_id, user_ip.ipv4_addrs, user_ip.ports),
            )
        except UniqueViolation as error:
            pool.putconn(connection)
            raise HTTPException(
                status_code=409, detail="ipv4(s) & port(s) already registered"
            ) from error

        connection.commit()
    pool.putconn(connection)


# scan ran by registered user for registered domain
@dispatch(models.UserDomain)
def start_scan(domain: models.UserDomain) -> str:

    scan_id = str(uuid.uuid4())
    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into scans
                (id, user_id, user_domain_id, domain, state) values (%s, %s, %s, %s, %s);
            """,
            (scan_id, domain.user_id, domain.id_, domain.domain, "IN_PROGRESS"),
        )
        connection.commit()
    pool.putconn(connection)

    return scan_id


# scan ran by unregistered user for unregistered domain
@dispatch(str, str)
def start_scan(domain: str, source_ipv4_addr: str) -> str:

    scan_id = str(uuid.uuid4())
    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into scans
                (id, domain, source_ipv4_addr, state) values (%s, %s, %s, %s);
            """,
            (scan_id, domain, source_ipv4_addr, "IN_PROGRESS"),
        )
        connection.commit()
    pool.putconn(connection)

    return scan_id


# scan ran by registered user for unregistered domain
@dispatch(str, models.User)
def start_scan(domain: str, user: models.User) -> str:

    scan_id = str(uuid.uuid4())
    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into scans
                (id, user_id, domain, state) values (%s, %s, %s, %s);
            """,
            (scan_id, user.id_, domain, "IN_PROGRESS"),
        )
        connection.commit()
    pool.putconn(connection)

    return scan_id


# scan ran by registered user for unregistered ipv4 and ports
@dispatch(str, str, models.User)
def start_scan(ipv4_addrs: str, ports: str, user: models.User) -> str:

    scan_id = str(uuid.uuid4())
    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into scans
                (id, user_id, ipv4_addrs, ports, state) values (%s, %s, %s, %s, %s);
            """,
            (scan_id, user.id_, ipv4_addrs, ports, "IN_PROGRESS"),
        )
        connection.commit()
    pool.putconn(connection)

    return scan_id


# scan ran by registered user for registered ipv4 and ports
@dispatch(models.UserIP)
def start_scan(ipv4: models.UserIP) -> str:

    scan_id = str(uuid.uuid4())
    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into scans
                (id, user_id, user_port_id, ipv4_addrs, ports, state)
                values
                (%s, %s, %s, %s, %s, %s);
            """,
            (
                scan_id,
                ipv4.user_id,
                ipv4.id_,
                ipv4.ipv4_addrs,
                ipv4.ports,
                "IN_PROGRESS",
            ),
        )
        connection.commit()
    pool.putconn(connection)

    return scan_id


# scan ran by unregistered user for unregistered ipv4 and ports
@dispatch(str, str, str)
def start_scan(ipv4_addrs: str, ports: str, source_ipv4_addr: str) -> str:

    scan_id = str(uuid.uuid4())
    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into scans
                (id, ipv4_addrs, ports, source_ipv4_addr, state)
                values
                (%s, %s, %s, %s, %s, %s);
            """,
            (scan_id, ipv4_addrs, ports, source_ipv4_addr, "IN_PROGRESS"),
        )
        connection.commit()
    pool.putconn(connection)

    return scan_id


def finish_scan(scan_id: str) -> None:

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            update scans set
                state = 'COMPLETED'
            where id = %s;
            """,
            (scan_id,),
        )
        connection.commit()
    pool.putconn(connection)


def store_domain_scan_results(scan_id: str, results: Dict) -> None:

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.executemany(
            """
            insert into domain_scan_results
                (scan_id, record_type, record_values) values (%s, %s, %s);
            """,
            [
                (scan_id, record_type, ", ".join(record_values))
                for record_type, record_values in results.items()
            ],
        )
        connection.commit()
    pool.putconn(connection)


def store_port_scan_results(results: List[Dict]) -> None:

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.executemany(
            """
            insert into port_scan_results
                (id, scan_id, host, host_state, port, port_state, protocol)
                values
                (%s, %s, %s, %s, %s, %s, %s);
            """,
            [
                (
                    result["id"],
                    result["scan_id"],
                    result["host"],
                    result["host_state"],
                    result["port"],
                    result["port_state"],
                    result["protocol"].upper(),
                )
                for result in results
            ],
        )
        connection.commit()
    pool.putconn(connection)


def store_ssl_cert_results(results: List[Dict]) -> None:

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.executemany(
            """
            insert into ssl_cert_results (
                scan_result_id, subject, subject_alternative_name,
                issuer, public_key_type, public_key_bits, signature_algorithm,
                not_valid_before, not_valid_after, md5, sha_1 )
                values
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            [
                (
                    result["scan_result_id"],
                    result["subject"],
                    result["subject_alternative_name"],
                    result["issuer"],
                    result["public_key_type"],
                    result["public_key_bits"],
                    result["signature_algorithm"],
                    result["not_valid_before"],
                    result["not_valid_after"],
                    result["md5"],
                    result["sha_1"],
                )
                for result in results
            ],
        )
        connection.commit()
    pool.putconn(connection)


def store_http_security_headers_results(results: List[Dict]) -> None:

    connection = pool.getconn()
    with connection.cursor() as cursor:
        cursor.executemany(
            """
            insert into http_security_headers_results (
                scan_result_id, header, value, description )
                values
                (%s, %s, %s, %s);
            """,
            [
                (
                    result["scan_result_id"],
                    result["header"],
                    result["value"],
                    result["description"],
                )
                for result in results
            ],
        )
        connection.commit()
    pool.putconn(connection)
