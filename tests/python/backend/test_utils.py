import utils


def test_count_zero_ports() -> None:
    assert utils.count_ports("") == 0


def test_count_single_port() -> None:
    assert utils.count_ports("443") == 1


def test_count_comma_sep_ports() -> None:
    assert utils.count_ports("443,80, 22,8080 ,9001") == 5


def test_count_dash_sep_ports() -> None:
    assert utils.count_ports("75-123") == 49


def test_is_valid_zero_ports() -> None:
    assert utils.is_valid_port("") == False


def test_is_valid_single_port() -> None:

    assert utils.is_valid_port("443") == True
    assert utils.is_valid_port("abc") == False


def test_is_valid_comma_sep_ports() -> None:

    assert utils.is_valid_port("443,80") == True
    assert utils.is_valid_port("22, 5432,8080 ,9001") == True
    assert utils.is_valid_port("22,9001, ") == False


def test_is_valid_dash_sep_ports() -> None:

    assert utils.is_valid_port("1-10") == True
    assert utils.is_valid_port("75-123") == True

    assert utils.is_valid_port("a-b") == False
    assert utils.is_valid_port("75 -123") == False


def test_is_valid_zero_ipv4() -> None:
    assert utils.is_valid_ipv4("") == False


def test_is_valid_single_ipv4() -> None:

    assert utils.is_valid_ipv4("127.0.0.1") == True
    assert utils.is_valid_ipv4("127.a.0.b") == False


def test_is_valid_cidr_ipv4() -> None:

    assert utils.is_valid_ipv4("8.8.8.8/12") == True
    assert utils.is_valid_ipv4("8.8.8.8/a") == False


def test_is_valid_dash_sep_ipv4() -> None:

    assert utils.is_valid_ipv4("8.8.8.8-2") == True

    assert utils.is_valid_ipv4("8.8.8.8-b") == False
    assert utils.is_valid_ipv4("8.8.8.8- 2") == False


def test_is_valid_space_sep_ipv4() -> None:

    assert utils.is_valid_ipv4("8.8.8.8 127.0.0.1") == True
    assert utils.is_valid_ipv4("8.8.8.8 b.0.0.1") == False
