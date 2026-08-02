"""`.env` handling — the one file in this repo that holds a real secret.

Every test here points `ENV_FILE` at a temporary path. None of them reads the
developer's actual `.env`, because a test that loads a real key puts it in
pytest's environment and one `-s` away from the terminal.
"""

import os
import subprocess
from pathlib import Path

import pytest

from src import env

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / ".env.example"
VARIABLE = "ANTHROPIC_API_KEY"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_real_environment_variable_beats_the_file(tmp_path, monkeypatch):
    """`override=False`. A shell export, a CI secret and an inline prefix all win.

    The reverse would make a stale `.env` silently shadow the key an operator
    just set on the command line — and the failure would look like an auth error
    from a key they are certain is right.
    """
    monkeypatch.setattr(env, "ENV_FILE", _write(tmp_path, f"{VARIABLE}=from-the-file\n"))
    monkeypatch.setenv(VARIABLE, "from-the-environment")

    env.load_env()

    assert os.environ[VARIABLE] == "from-the-environment"


def test_the_file_is_used_when_the_environment_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(env, "ENV_FILE", _write(tmp_path, f"{VARIABLE}=from-the-file\n"))
    monkeypatch.delenv(VARIABLE, raising=False)

    env.load_env()

    assert os.environ[VARIABLE] == "from-the-file"


def test_a_missing_file_is_not_an_error(tmp_path, monkeypatch):
    """The deterministic core imports nothing from here, but `--help` and a
    usage error on the model-calling entry points must not need a key."""
    monkeypatch.setattr(env, "ENV_FILE", tmp_path / "absent")
    monkeypatch.delenv(VARIABLE, raising=False)

    env.load_env()

    assert VARIABLE not in os.environ


def test_the_example_declares_the_variable_the_sdk_actually_reads():
    """Drift between the documented name and the read name is silent until a run.

    `ANTHROPIC-API-KEY` with hyphens parses as a perfectly valid assignment and
    the SDK never looks at it, so the failure surfaces as "no key" against a file
    that visibly contains one.
    """
    declared = [
        line.split("=", 1)[0].strip()
        for line in EXAMPLE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#") and "=" in line
    ]
    assert declared == [VARIABLE]


def test_the_example_carries_no_value():
    """It is tracked, so anything to the right of `=` is committed and permanent."""
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.strip().startswith("#"):
            assert line.split("=", 1)[1].strip() == ""


@pytest.mark.parametrize(
    ("path", "ignored"),
    [(".env", True), (".env.example", False)],
    ids=["the key file cannot be committed", "the template must be committable"],
)
def test_gitignore_draws_the_line_in_the_right_place(path, ignored):
    """The boundary the whole threat model rests on, asserted rather than assumed.

    `check-ignore` exits 0 when a path is ignored and 1 when it is not. Committing
    `.env` is the failure mode this repo is about; failing to commit `.env.example`
    would just leave a reader with no idea what to set.
    """
    result = subprocess.run(
        ["git", "check-ignore", "-q", path], cwd=ROOT, capture_output=True
    )
    assert (result.returncode == 0) is ignored
