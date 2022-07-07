from backend import __version__


def test_version() -> None:
    assert __version__ == "1.3.1"
