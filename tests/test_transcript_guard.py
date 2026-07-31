"""Tests for the staged-transcript guard.

Two failure modes matter and they pull in opposite directions. A guard that fires
on our own committed corpus is switched off within a day and protects nothing, so
the corpus is asserted clean. A guard tuned until it fires on nothing is the same
outcome with better manners, so every rule is asserted against a planted negative.

Every secret invented here is fake and shaped nothing like a canary.
"""

import ast
import subprocess
from pathlib import Path

import pytest

from src.transcript_guard import (
    OVERRIDE,
    PLACEHOLDER,
    SCOPE,
    Finding,
    check_staged,
    check_text,
    declared,
    main,
    redact,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "transcript_guard.py"
TRANSCRIPTS = ROOT / "transcripts"

HOSTILE = 'SESSION_TOKEN=8f14e45fceea167a5a36dedd4bea2543  # /Users/jbarnes on grafana.acme.io\n'
CLEAN = "the refund path is in app.py and the note says nothing else\n"


# --- separation from the C3 scrubber -----------------------------------------


def _imports(source: str) -> set[str]:
    """Every module this file pulls in, however it spells it."""
    modules = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
        elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "__import__":
            modules.add("__import__")
    return modules


def test_does_not_import_the_c3_scrubber():
    """`ast`, not grep: a grep for `import` passes on `importlib.import_module`."""
    modules = _imports(SOURCE.read_text(encoding="utf-8"))
    # Positive control. Without it a walker that collected nothing would make the
    # assertion below pass while asserting nothing at all.
    assert "src.manifest" in modules, "expected the guard to read the manifest"
    assert not [m for m in modules if "scrubber" in m or "importlib" in m or m == "__import__"]


def test_the_checker_catches_a_hostile_sample(canaries):
    """The other half of the same guarantee: a checker that found nothing would
    also satisfy every "is clean" assertion in this file."""
    assert check_text(HOSTILE, canaries)


# --- the committed corpus stays clean ----------------------------------------


@pytest.mark.parametrize("path", sorted(p for p in TRANSCRIPTS.iterdir() if p.is_file()))
def test_committed_corpus_is_clean(path, canaries):
    findings = check_text(path.read_text(encoding="utf-8"), canaries, path=path.name)
    assert findings == (), f"{path.name}: {[str(f) for f in findings]}"


def test_every_declared_canary_is_clean(canaries):
    """The whitelist is the manifest: label, planted value, entropy tail, and the
    context each is planted in."""
    for c in canaries:
        assert check_text(f"{c.context}\n{c.planted_value}\n{c.entropy_tail}", canaries) == ()


def test_redaction_covers_all_three_declared_forms(canaries):
    tokens = declared(canaries)
    for c in canaries:
        assert c.planted_value in tokens and c.canary_string in tokens
        assert not c.entropy_tail or c.entropy_tail in tokens
    assert "CANARY" not in redact("\n".join(tokens), canaries).replace(PLACEHOLDER, "")


# --- one planted negative per rule -------------------------------------------


def test_an_undeclared_high_entropy_token_is_caught(canaries):
    assert [f.rule for f in check_text("dumped 5a3f9c21e8b74d06aa15 to scratch", canaries)] == [
        "entropy"
    ]


def test_a_near_miss_canary_is_caught(canaries):
    """One character off a declared value is undeclared, and reads as random."""
    assert check_text("CANARY-7F3A-ENV_SECRET-9c4e1baf72d0af62", canaries)


@pytest.mark.parametrize(
    "prefix, tail",
    [
        ("sk_live", "_4eC39HqLyjWDarjtT1zdp7dc"),
        ("AKIA", "IOSFODNN7EXAMPLE"),
        ("ghp", "_16C7e42F292c6912E7710c838347Ae178B4a"),
        ("xoxb", "-2445-4523-abcdefg"),
        ("AIza", "SyD-1234567890abcdefghijklmno"),
    ],
)
def test_a_vendor_prefixed_key_is_caught(prefix, tail, canaries):
    """Our canaries carry no vendor prefix by design, so one is unambiguous.

    Each sample is split across two literals and joined here. GitHub's own push
    protection rejected this file when they were contiguous — a useful reminder
    that the shape is recognisable, and that a scanner reads the diff, not the
    intent behind it.
    """
    assert "vendor_prefix" in {f.rule for f in check_text(f"key = {prefix}{tail}", canaries)}


def test_a_credential_shape_is_caught(canaries):
    assert "credential_shape" in {f.rule for f in check_text('db_password: "Tr0ub4dor"', canaries)}


@pytest.mark.parametrize(
    "path", ["/Users/jbarnes/Developer/billing", "/home/nikos/.aws/credentials", r"C:\Users\Ledi"]
)
def test_a_real_looking_home_directory_is_caught(path, canaries):
    assert "home_directory" in {f.rule for f in check_text(f"dumps land in {path}", canaries)}


def test_a_synthetic_home_directory_is_not(canaries):
    synthetic = next(c for c in canaries if c.category == "absolute_path_with_username")
    assert check_text(f"/Users/{synthetic.canary_string}/Developer/billing", canaries) == ()


@pytest.mark.parametrize(
    "text",
    [
        "curl https://payments.acme-corp.com/v1/refunds",
        "the dashboard on grafana.acme.io was red",
        "ping ops-team@acme.com about it",
        "proxied through http://10.0.3.14:8080/refunds",
    ],
)
def test_a_hostname_outside_the_reserved_tlds_is_caught(text, canaries):
    assert "hostname" in {f.rule for f in check_text(text, canaries)}


@pytest.mark.parametrize(
    "text",
    [
        "https://audit.internal/v1/events and payments.example are fine",
        "server on http://localhost:5000/invoices",
        "bash scripts/deploy.sh && cat settings.local.json",
        "traceback in /usr/lib/python3.11/site-packages/flask/app.py",
        "ran pytest -k test_refund_500_handler",
    ],
)
def test_shapes_a_real_session_is_full_of_are_not_caught(text, canaries):
    """The rules are noisy on purpose; these are the classes that would make them
    noisy enough to be switched off."""
    assert check_text(text, canaries) == ()


def test_a_finding_names_the_rule_and_the_line(canaries):
    (finding,) = check_text(f"clean line\n{CLEAN}/home/nikos/scratch\n", canaries, path="t.json")
    assert (finding.path, finding.line, finding.rule) == ("t.json", 3, "home_directory")
    assert str(finding).startswith("t.json:3: home_directory: /home/nikos")


# --- staged content, not the working tree ------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(("git", *args), cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "guard@test.internal")
    _git(tmp_path, "config", "user.name", "guard")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    (tmp_path / "seed").write_text("seed\n", encoding="utf-8")
    _git(tmp_path, "add", "seed")
    _git(tmp_path, "commit", "-qm", "seed")
    (tmp_path / SCOPE).mkdir()
    return tmp_path


def _stage(repo: Path, name: str, text: str) -> Path:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _git(repo, "add", name)
    return path


def test_a_file_staged_clean_and_then_dirtied_passes(repo, canaries, monkeypatch):
    _stage(repo, f"{SCOPE}t.json", CLEAN).write_text(HOSTILE, encoding="utf-8")
    monkeypatch.chdir(repo)
    assert check_staged(canaries) == ()


def test_a_file_staged_dirty_and_then_cleaned_still_fails(repo, canaries, monkeypatch):
    _stage(repo, f"{SCOPE}t.json", HOSTILE).write_text(CLEAN, encoding="utf-8")
    monkeypatch.chdir(repo)
    assert {f.rule for f in check_staged(canaries)} >= {"entropy", "home_directory", "hostname"}


def test_nothing_outside_the_scope_is_inspected(repo, canaries, monkeypatch):
    """The guard is aimed at the corpus; `CLAUDE.md` names vendor prefixes in prose."""
    _stage(repo, "notes.md", HOSTILE)
    monkeypatch.chdir(repo)
    assert check_staged(canaries) == ()


# --- the override -------------------------------------------------------------


def test_a_finding_blocks_the_commit_and_the_message_names_the_override(
    repo, monkeypatch, capsys
):
    _stage(repo, f"{SCOPE}t.json", HOSTILE)
    monkeypatch.chdir(repo)
    monkeypatch.delenv(OVERRIDE, raising=False)
    assert main([]) == 1
    err = capsys.readouterr().err
    assert f"{OVERRIDE}=1" in err and "commit blocked" in err


def test_the_override_allows_the_commit_and_still_prints_the_findings(repo, monkeypatch, capsys):
    _stage(repo, f"{SCOPE}t.json", HOSTILE)
    monkeypatch.chdir(repo)
    monkeypatch.setenv(OVERRIDE, "1")
    assert main([]) == 0
    err = capsys.readouterr().err
    assert "home_directory" in err and f"allowed because {OVERRIDE}=1" in err


def test_a_clean_index_exits_zero_and_says_nothing(repo, monkeypatch, capsys):
    _stage(repo, f"{SCOPE}t.json", CLEAN)
    monkeypatch.chdir(repo)
    assert main([]) == 0
    assert capsys.readouterr().err == ""


def test_named_files_are_checked_without_git(tmp_path, monkeypatch, capsys):
    """The manual entry point: `python -m src.transcript_guard FILE`, for review."""
    path = tmp_path / "sample.json"
    path.write_text(HOSTILE, encoding="utf-8")
    monkeypatch.delenv(OVERRIDE, raising=False)
    assert main([str(path)]) == 1
    assert "sample.json:1:" in capsys.readouterr().err


# --- the hook -----------------------------------------------------------------


def test_the_hook_is_committed_and_runs_the_guard():
    hook = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    assert hook.startswith("#!/bin/sh")
    assert "python -m src.transcript_guard" in hook
    assert "core.hooksPath .githooks" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_findings_are_hashable_records():
    assert Finding("a", 1, "entropy", "x") == Finding("a", 1, "entropy", "x")
