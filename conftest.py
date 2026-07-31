import pytest

from scripts.build_fixture import build
from src.manifest import load as load_canaries


@pytest.fixture(scope="session")
def canaries():
    return load_canaries()


@pytest.fixture(scope="session")
def fixture_root(tmp_path_factory, canaries):
    """A freshly built fixture in a temp dir.

    Never the real `fixture/`: tests must not depend on a developer having run the
    generator, and `build()` opens with an unguarded `rmtree` of its target (#31).
    """
    root = tmp_path_factory.mktemp("fixture")
    build(root, canaries)
    return root
