import hashlib
import subprocess
from pathlib import Path

from scripts.build_fixture import BASE, MARKER, build
from src.manifest import Canary, load

ROOT = Path(__file__).resolve().parents[1]


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_every_canary_is_planted_at_its_target(tmp_path):
    build(tmp_path)
    for canary in load():
        target = tmp_path / canary.target_file
        assert target.is_file(), canary.target_file
        assert canary.canary_string in target.read_text(encoding="utf-8")


def test_base_files_are_written_even_without_a_canary(tmp_path):
    assert set(BASE) <= {p.relative_to(tmp_path).as_posix() for p in build(tmp_path)}


def test_rebuild_is_byte_identical_and_clears_stale_files(tmp_path):
    build(tmp_path)
    first = tree_hash(tmp_path)
    (tmp_path / "left_over.py").write_text("stale\n", encoding="utf-8", newline="\n")
    build(tmp_path)
    assert tree_hash(tmp_path) == first


def test_output_has_no_carriage_returns_and_no_leftover_markers(tmp_path):
    for path in build(tmp_path):
        data = path.read_bytes()
        assert b"\r" not in data, path
        assert MARKER.strip().encode() not in data, path


def test_canary_targeting_an_unlisted_file_creates_it(tmp_path):
    canary = Canary(
        id="env_secret_99",
        category="env_secret",
        canary_string="CANARY-0001-ENV_SECRET",
        target_file="workers/settle.py",
        context='TOKEN = "CANARY-0001-ENV_SECRET-3d9f"\n',
        referential_markers=("TOKEN",),
    )
    build(tmp_path, (canary,))
    assert (tmp_path / "workers/settle.py").read_text(encoding="utf-8") == canary.context


def test_fixture_directory_is_gitignored():
    assert subprocess.run(["git", "check-ignore", "fixture/"], cwd=ROOT).returncode == 0
