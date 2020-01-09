import pytest


def e():
    raise SystemExit(1)


def test_exception():
    with pytest.raises(SystemExit):
        e()
