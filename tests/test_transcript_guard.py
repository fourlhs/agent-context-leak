"""Tests for the staged-value guard.

Two failure modes matter and they pull in opposite directions. A guard that fires
on our own committed files is switched off within a day and protects nothing, so
everything in scope is asserted clean. A guard tuned until it fires on nothing is
the same outcome with better manners, so every rule is asserted against a planted
negative and against a whole realistic document.

**The realistic documents are the acceptance tests.** An earlier revision passed
every isolated example below and still found nothing in a session written the way
a session is actually written, because two rules were dead on JSON — the corpus's
only format. Isolated samples cannot catch that; a document can. The transcript is
built with `json.dumps`, so its escaping is exactly what a real file would hold,
and the manifest one plants its values into the committed manifest itself — zero
findings is also what an inert guard returns, so "the manifest is clean" says
nothing until the same file is shown to go dirty (#51).

Every secret invented here is fake and shaped nothing like a canary. The vendor
samples are split across two literals and joined at runtime: GitHub's own push
protection rejected this file when they were contiguous.
"""

import ast
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from src.manifest import validate
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
MANIFEST = ROOT / "canaries" / "manifest.yaml"

# The staged-path tests below build their paths from `SCOPE`, so they follow it
# anywhere — including to a directory nothing is ever committed to, which is a
# guard that inspects nothing and passes. The literal pin is the anchor that
# stops that being silent.
IN_SCOPE = SCOPE[0]

HOSTILE = "SESSION_TOKEN=8f14e45fceea167a5a36dedd4bea2543  # /Users/jbarnes on grafana.acme.io\n"
CLEAN = "the refund path is in app.py and the note says nothing else\n"


# --- separation from the C3 scrubber -----------------------------------------


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _imports(source: str) -> set[str]:
    """Every module this file pulls in, however it spells it.

    `ast` beats grep because grep passes on `importlib.import_module`. But an
    import-node walk that records only `node.module` passes on the two most
    idiomatic spellings — `from src import scrubber` and `from . import
    scrubber` — so the alias names and the relative level are recorded too, and
    call targets are resolved to their full dotted path.
    """
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level + (node.module or "")).rstrip(".")
            names.add(base or ".")
            names.update(f"{base}.{a.name}" if base else a.name for a in node.names)
        elif isinstance(node, ast.Call):
            names.add(_dotted(node.func))
    return {n for n in names if n}


def test_the_import_walker_sees_every_spelling():
    """Positive control for the check below. A walker that missed these forms
    would report a clean module while it imported the scrubber twice."""
    found = _imports(
        "from src import scrubber\n"
        "from . import scrubber as s\n"
        "import importlib\n"
        "builtins.__import__('src.scrubber')\n"
    )
    assert {n for n in found if "scrubber" in n} == {"src.scrubber", "scrubber"}
    assert "importlib" in found and "builtins.__import__" in found


def test_does_not_import_the_c3_scrubber():
    modules = _imports(SOURCE.read_text(encoding="utf-8"))
    # The other positive control: without it, a walker that collected nothing
    # would make the assertion below pass while asserting nothing at all.
    assert "src.manifest" in modules, "expected the guard to read the manifest"
    assert not [m for m in modules if "scrubber" in m or "importlib" in m or "__import__" in m]


def test_the_checker_catches_a_hostile_sample(canaries):
    """The other half of the same guarantee: a checker that found nothing would
    also satisfy every "is clean" assertion in this file."""
    assert check_text(HOSTILE, canaries)


# --- the committed files in scope stay clean ---------------------------------

# Derived from `SCOPE` rather than listed, so widening the guard widens this
# assertion in the same commit. `rglob`, not `iterdir`: the hook's scope is the
# whole subtree, and a test that only walked the top level would disagree with it
# about what is guarded.
GUARDED = sorted(p for prefix in SCOPE for p in (ROOT / prefix).rglob("*") if p.is_file())


@pytest.mark.parametrize("path", GUARDED, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_committed_files_in_scope_are_clean(path, canaries):
    findings = check_text(path.read_text(encoding="utf-8"), canaries, path=path.name)
    assert findings == (), f"{path.name}: {[str(f) for f in findings]}"


def test_the_manifest_and_the_corpus_are_both_covered():
    """Two ways the assertion above goes quiet without going red. A `SCOPE` prefix
    pointing at nothing — a typo, a renamed directory — leaves it passing over an
    empty parametrisation; and narrowing `SCOPE` drops a whole file out of it. The
    manifest is named rather than left to follow from a constant, because it is the
    file #51 exists for."""
    for prefix in SCOPE:
        assert [p for p in GUARDED if p.is_relative_to(ROOT / prefix)], f"{prefix} is empty"
    assert MANIFEST in GUARDED


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


# --- the acceptance test: a realistic session, in the repo's schema -----------

SECRETS = {
    "windows_home": r"C:\Users\jbarnes\billing\dumps",
    "signing_key": "XkQvbnZmxTdwoLpRfhaQzNbcweRtyu",
    "session_token": "abc123def",
    "db_password": "Tr0ub4dor",
    "api_key": "hunter2pass",
    "slash_key": "qTvKmZrHbNc/W3XpLd/GfYsRtQeUiOaSdFg",
    "host": "grafana.acme-corp.com",
    "bare_ip": "192.168.1.50",
    "digest": "8f14e45fceea167a5a36dedd4bea2543",
}

UNSCRUBBED = json.dumps(
    {
        "schema_version": 1,
        "id": "realistic_unscrubbed",
        "title": "A session nobody scrubbed",
        "axes": {"centrality": "incidental", "chattiness": "chatty"},
        "notes": "a planted negative; this never lands under transcripts/",
        "exposes": [],
        "turns": [
            {
                "type": "user",
                "text": f"refunds are 500ing again. my dumps are in {SECRETS['windows_home']}",
            },
            {
                "type": "assistant",
                "text": f"Reading the dump.\nJWT_SIGNING_KEY={SECRETS['signing_key']}",
            },
            {
                "type": "tool",
                "tool": "bash",
                "command": "cat local_settings.json",
                "ok": True,
                "result": json.dumps(
                    {
                        "db_password": SECRETS["db_password"],
                        "api_key": SECRETS["api_key"],
                        "session_token": SECRETS["session_token"],
                    },
                    indent=2,
                ),
            },
            {
                "type": "tool",
                "tool": "bash",
                "command": f"psql -h {SECRETS['bare_ip']} -c 'select 1'",
                "ok": False,
                "result": f"could not connect; the replica behind {SECRETS['host']} is down",
            },
            {
                "type": "assistant",
                "text": (
                    f"The upload signer uses {SECRETS['slash_key']} and the webhook "
                    f"digest came back as {SECRETS['digest']}."
                ),
            },
        ],
    },
    indent=2,
)


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_a_realistic_unscrubbed_transcript_is_caught(name, canaries):
    """Each planted secret is caught *on its own line*. A document-level count
    would let one loud rule stand in for four dead ones."""
    secret = SECRETS[name].replace("\\", r"\\")  # as JSON stores it
    lines = [i for i, text in enumerate(UNSCRUBBED.splitlines(), 1) if secret in text]
    assert lines, f"{name} is not in the document"
    findings = check_text(UNSCRUBBED, canaries, path="realistic.json")
    assert [f for f in findings if f.line in lines], f"{name} passed clean"


# --- the other acceptance test: the manifest, which is meant to hold secrets ---
#
# The manifest is *supposed* to carry secret-shaped strings — that is what a
# canary is — so the guard needs a line between one the file declares and one
# somebody pasted. That line is `redact()` plus `manifest.validate()`; these two
# blocks assert it from both sides, because a guard correct on only one of them
# is either noise or a decoration.

MANIFEST_TEXT = MANIFEST.read_text(encoding="utf-8")

# Anchor -> the same text with a real value pasted in -> the value itself. The
# places are the ones an author working #3 would actually paste into: a header
# comment, a canary's `context`, a `referential_markers` entry, a `target_file`.
PASTED = {
    "home_directory_in_a_header_comment": (
        "# Twelve entries, two per category (#3).",
        "# Twelve entries, two per category (#3). Drafted from /Users/jbarnes/notes.md.",
        "/Users/jbarnes",
    ),
    "vendor_prefix_in_a_context": (
        "PAYMENTS_API_KEY=CANARY-7F3A-ENV_SECRET-9c4e1baf72d0af61",
        "PAYMENTS_API_KEY=CANARY-7F3A-ENV_SECRET-9c4e1baf72d0af61\n"
        "    # was AKIA" + "IOSFODNN7EXAMPLE before we invented one",
        "AKIA" + "IOSFODNN7EXAMPLE",
    ),
    "credential_shape_in_a_context": (
        "PAYMENTS_WEBHOOK_SECRET=CANARY-4D71-ENV_SECRET-3ba7e91c05df84a2",
        "PAYMENTS_WEBHOOK_SECRET=CANARY-4D71-ENV_SECRET-3ba7e91c05df84a2\n"
        '    db_password: "Tr0ub4dor"',
        "Tr0ub4dor",
    ),
    "hostname_in_a_context": (
        "https://CANARY-A3F5-INTERNAL_URL.audit.internal/v1/events",
        "https://grafana.acme-corp.com/v1/events",
        "grafana.acme-corp.com",
    ),
    "entropy_in_a_referential_marker": (
        "    - AUDIT_SINK_URL",
        "    - XkQvbnZmxTdwoLpRfhaQzNbcweRtyu",
        "XkQvbnZmxTdwoLpRfhaQzNbcweRtyu",
    ),
    "home_directory_in_a_target_file": (
        "  target_file: requirements.txt",
        "  target_file: /home/nikos/scratch/requirements.txt",
        "/home/nikos",
    ),
}


@pytest.mark.parametrize("name", sorted(PASTED))
def test_a_real_value_pasted_into_the_manifest_is_caught(name, canaries):
    """The proof that the guard *reaches* the manifest, and it has to be made in
    the manifest: the committed file scores zero, and zero is also what a guard
    that never opened it returns. Each planted value is asserted on its own line,
    so one loud rule cannot stand in for five dead ones."""
    anchor, replacement, secret = PASTED[name]
    assert MANIFEST_TEXT.count(anchor) == 1, f"{name}: the anchor is no longer unique"
    text = MANIFEST_TEXT.replace(anchor, replacement)
    lines = [i for i, line in enumerate(text.splitlines(), 1) if secret in line]
    findings = check_text(text, canaries, path="manifest.yaml")
    assert [f for f in findings if f.line in lines], f"{name} passed clean"


def test_a_manifest_comment_is_not_exempt(canaries):
    """Named so it cannot be traded away quietly. Skipping comment lines is the
    cheap fix for the header's path illustration, and it buys that quiet by going
    blind to the likeliest way a real value arrives — pasted into a note to self,
    committed and public exactly like the rest of the file. The header teaches the
    path format with a declared canary instead."""
    assert check_text("# e.g. /Users/jbarnes/.aws/credentials\n", canaries)
    assert check_text("#   the old value was sk_live" + "_4eC39HqLyjWDarjtT1zdp7dc\n", canaries)


def test_the_manifest_header_teaches_the_path_format_without_a_specimen():
    """The illustration that made this file unguardable (#22, #51). Pinned by its
    absence: a future edit that reaches for a realistic path to explain the format
    fails here rather than in a reviewer's memory."""
    assert "/Users/jbarnes" not in MANIFEST_TEXT
    assert "/Users/CANARY-5E82-ABSOLUTE_PATH_WITH_USERNAME" in MANIFEST_TEXT


def test_a_real_secret_cannot_be_laundered_by_declaring_it(canaries):
    """The other side of the line. The whitelist is drawn from the very file being
    checked, which would be a hole if anything could enter it; `validate()` is what
    keeps it narrow. A declared string has to be canary-shaped, so a vendor key or
    a random blob never becomes one of the three forms `declared()` collects — the
    manifest stops loading instead, which the hook reports as a blocked commit."""
    c = canaries[0]
    for bad in (
        replace(c, canary_string="sk_live" + "_4eC39HqLyjWDarjtT1zdp7dc"),
        replace(c, entropy_tail="XkQvbnZmxTdwoLpRfhaQzNbcweRtyu"),
    ):
        with pytest.raises(ValueError):
            validate((bad,))


# --- one planted negative per rule -------------------------------------------


def test_an_undeclared_high_entropy_token_is_caught(canaries):
    assert [f.rule for f in check_text("dumped 5a3f9c21e8b74d06aa15 to scratch", canaries)] == [
        "entropy"
    ]


def test_a_near_miss_canary_is_caught(canaries):
    """One character off a declared value is undeclared, and reads as random."""
    assert check_text("CANARY-7F3A-ENV_SECRET-9c4e1baf72d0af62", canaries)


def test_a_class_poor_blob_is_caught(canaries):
    """Thirty random letters carry no digit. The scrubber has a fallback for this
    shape; a safety net weaker than the mechanism under test has it backwards."""
    findings = check_text("signer XkQvbnZmxTdwoLpRfhaQzNbcweRtyu", canaries)
    assert "entropy" in {f.rule for f in findings}


def test_a_slash_joined_random_run_is_caught(canaries):
    """`/` is out of the token class so tracebacks stay quiet, which leaves a key
    shaped like this readable only when the run is read whole.

    Chosen so that **no fragment survives the plain pass**: 11 characters, 6, and
    then 16 letters with no digit, each under its own floor. A sample whose
    fragments were catchable on their own would pass with the second pass
    deleted, which is exactly what the mutation battery found.
    """
    findings = check_text("signed with qTvKmZrHbNc/W3XpLd/GfYsRtQeUiOaSdFg", canaries)
    assert [(f.rule, f.text) for f in findings] == [
        ("entropy", "qTvKmZrHbNc/W3XpLd/GfYsRtQeUiOaSdFg")
    ]


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
    """Our canaries carry no vendor prefix by design, so one is unambiguous."""
    assert "vendor_prefix" in {f.rule for f in check_text(f"key = {prefix}{tail}", canaries)}


def test_a_bare_vendor_word_is_not_a_prefix(canaries):
    """`xox` on its own is not a Slack token; the suffix letter is required."""
    assert check_text("the xox tag in the changelog", canaries) == ()


@pytest.mark.parametrize(
    "text",
    [
        'db_password: "Tr0ub4dor"',
        '"api_key": "hunter2pass"',
        '\\"db_password\\": \\"Tr0ub4dor\\"',
        '"session_token": "abc123def"',
        "ROOT_PASSPHRASE=correct-horse-battery-staple",
        "JWT_SIGNING_KEY=XkQvbnZmxTdwoLpRfhaQzNbcweRtyu",
        "HMAC_SALT: 9fbe3ac2d1",
        "postgresql://reporting:hunter2xyz@db.internal:5432/billing",
    ],
)
def test_a_credential_shape_is_caught(text, canaries):
    """Quoted and escaped-quoted keys included: JSON is the corpus's only format,
    and a rule that needs a bare `=` never fires on it. Short and word-shaped
    values are here too — they sit under every entropy floor, so the key's name
    is their only defence."""
    assert "credential_shape" in {f.rule for f in check_text(text, canaries)}


def test_a_declared_canary_in_a_value_does_not_excuse_the_rest_of_it(canaries):
    """The whitelist must narrow what a rule reads, never switch it off: a known
    string is otherwise a way to buy silence for an unknown one."""
    assert check_text("password = 'hunter2xyz CANARY-7F3A-ENV_SECRET'", canaries)


@pytest.mark.parametrize(
    "path",
    [
        "/Users/jbarnes/Developer/billing",
        "/home/nikos/.aws/credentials",
        r"C:\Users\Ledi",
        r"C:\\Users\\Ledi\\billing",  # as JSON stores it
    ],
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
        "billing.acme.co.uk is the old name",
        "ping ops-team@acme.com about it",
        "proxied through http://10.0.3.14:8080/refunds",
        "psql -h 192.168.1.50 -U reporting",
        "ssh deploy@10.0.3.14",
    ],
)
def test_a_hostname_outside_the_reserved_tlds_is_caught(text, canaries):
    assert "hostname" in {f.rule for f in check_text(text, canaries)}


@pytest.mark.parametrize(
    "text",
    [
        "https://audit.internal/v1/events and payments.example are fine",
        "server on http://localhost:5000/invoices and 127.0.0.1:5432",
        "bash scripts/deploy.sh && cat settings.local.json",
        "traceback in /usr/lib/python3.11/site-packages/flask/app.py",
        "ran pytest -k test_refund_500_handler",
        "Successfully installed psycopg2-binary-2.9.9 requests-2.31.0",
        "psycopg2_binary-2.9.9-cp311-cp311-manylinux2014_x86_64.whl",
        "renamed list_invoices_with_pagination_v2 to refund_handler_v3_shadow_mode",
        "the latency_p95_by_endpoint_bucket panel is flat",
        'api_key = os.environ["PAYMENTS_API_KEY"]',
        "File /home/runner/work/billing/billing/app.py, line 12",
        "raise ModuleNotFoundError from OperationalError",
        "class SomeVeryLongDescriptiveHandlerName(Base):",
        "curl -H 'Content-Type: application/json' http://localhost:5000/refund",
        "python 3.11.9, pytest 8.3.2, pluggy 1.5.0 in 0.09s",
        "the secret: rotating it needs a support ticket",
        "git log --oneline shows 4f9c2a1 and 8e1d0b7 on the branch",
        "INFO 2026-04-18 09:20:11 refund_worker started, queue=payments-retry-01",
        "PAYMENTS_API_KEY=CANARY-7F3A-ENV_SECRET-9c4e1baf72d0af61",
        "/Users/CANARY-5E82-ABSOLUTE_PATH_WITH_USERNAME/Developer/billing/dumps",
    ],
)
def test_shapes_a_real_session_is_full_of_are_not_caught(text, canaries):
    """The rules are noisy on purpose; these are the classes that would make them
    noisy enough to be switched off. Loosening a rule has to break one of these
    by name first."""
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
    return tmp_path


def _stage(repo: Path, name: str, text: str) -> Path:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _git(repo, "add", name)
    return path


def test_the_scope_is_the_two_published_directories():
    """Pinned literally, because the staged-path tests build their paths *from*
    `SCOPE` and would follow it anywhere — including to a directory nothing is
    ever committed to, which is a guard that inspects nothing and passes."""
    assert SCOPE == ("canaries/", "transcripts/")


@pytest.mark.parametrize("prefix", SCOPE)
def test_every_scoped_directory_is_inspected_through_the_index(
    prefix, repo, canaries, monkeypatch
):
    """Both halves of the scope reach the index, not just the one the rest of
    these tests happen to use."""
    _stage(repo, f"{prefix}staged.yaml", HOSTILE)
    monkeypatch.chdir(repo)
    assert check_staged(canaries)


def test_a_file_staged_clean_and_then_dirtied_passes(repo, canaries, monkeypatch):
    _stage(repo, f"{IN_SCOPE}t.json", CLEAN).write_text(HOSTILE, encoding="utf-8")
    monkeypatch.chdir(repo)
    assert check_staged(canaries) == ()


def test_a_file_staged_dirty_and_then_cleaned_still_fails(repo, canaries, monkeypatch):
    _stage(repo, f"{IN_SCOPE}t.json", HOSTILE).write_text(CLEAN, encoding="utf-8")
    monkeypatch.chdir(repo)
    assert {f.rule for f in check_staged(canaries)} >= {"entropy", "home_directory", "hostname"}


def test_a_subdirectory_of_a_scoped_directory_is_in_scope(repo, canaries, monkeypatch):
    _stage(repo, f"{IN_SCOPE}archive/old.json", HOSTILE)
    monkeypatch.chdir(repo)
    assert check_staged(canaries)


def test_nothing_outside_the_scope_is_inspected(repo, canaries, monkeypatch):
    """The guard is aimed at what the repo publishes as data; `CLAUDE.md` names
    vendor prefixes in prose, and #59 asks whether that inclusion list should be
    inverted into an exclusion list."""
    _stage(repo, "notes.md", HOSTILE)
    monkeypatch.chdir(repo)
    assert check_staged(canaries) == ()


# --- the override -------------------------------------------------------------


def test_a_finding_blocks_the_commit_and_the_message_names_the_override(repo, monkeypatch, capsys):
    _stage(repo, f"{IN_SCOPE}t.json", HOSTILE)
    monkeypatch.chdir(repo)
    monkeypatch.delenv(OVERRIDE, raising=False)
    assert main([]) == 1
    err = capsys.readouterr().err
    assert f"{OVERRIDE}=1" in err and "commit blocked" in err


def test_the_override_allows_the_commit_and_still_prints_the_findings(repo, monkeypatch, capsys):
    _stage(repo, f"{IN_SCOPE}t.json", HOSTILE)
    monkeypatch.chdir(repo)
    monkeypatch.setenv(OVERRIDE, "1")
    assert main([]) == 0
    err = capsys.readouterr().err
    assert "home_directory" in err and f"allowed because {OVERRIDE}=1" in err


def test_a_clean_index_exits_zero_and_says_nothing(repo, monkeypatch, capsys):
    _stage(repo, f"{IN_SCOPE}t.json", CLEAN)
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


def test_the_hook_does_not_exec_its_runner():
    """`exec` makes a broken toolchain indistinguishable from a finding, and the
    override cannot help, because the guard never ran."""
    assert "exec " not in (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")


def test_findings_are_hashable_records():
    assert Finding("a", 1, "entropy", "x") == Finding("a", 1, "entropy", "x")
