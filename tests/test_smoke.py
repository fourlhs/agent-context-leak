import sys


def test_baseline():
    assert sys.version_info >= (3, 11)
    import src  # noqa: F401
