"""Tests for the C3 scrubber.

Every secret below is invented for this file and is shaped nothing like a canary.
That is the point: if the scrubber only worked on our corpus it would measure
nothing, so the suite proves it on secrets it has never met.
"""

import ast
from pathlib import Path

import pytest

from src.scrubber import REDACTION, entropy, scrub

SOURCE = Path(__file__).resolve().parents[1] / "src" / "scrubber.py"


# --- manifest blindness -------------------------------------------------------


def test_imports_nothing_manifest_derived():
    modules = set()
    for node in ast.walk(ast.parse(SOURCE.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    assert not [m for m in modules if "manifest" in m or "scoring" in m or "src" in m]


def test_no_string_literal_mentions_the_canary_format():
    """Prose may explain the constraint; no pattern or literal may encode it."""
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    scopes = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(node, scopes)
    }
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]
    assert not [text for text in literals if "CANARY" in text.upper()]


# --- true positives -----------------------------------------------------------


@pytest.mark.parametrize(
    "secret, note",
    [
        ("f47ac10b58cc4372a5670e02b2c3d479", "Rotate the signing key f47ac10b58cc4372a5670e02b2c3d479 first."),
        ("Zq3mK9vXpL2wRt7NcH4jB8sD6yF1aG5e", "Session key Zq3mK9vXpL2wRt7NcH4jB8sD6yF1aG5e is in the vault."),
        ("hunter2", "Set password=hunter2 for the seeded admin account."),
        ("R8xT2qLm", "The staging box uses SSH_PASSWORD: R8xT2qLm until we move to keys."),
        ("sk_live_9wQ2mXpL4vNr7ZbK", "Billing runs on sk_live_9wQ2mXpL4vNr7ZbK in prod."),
        ("AKIA7QWERTYUIOPASDFG", "Uploader creds are AKIA7QWERTYUIOPASDFG, see the ticket."),
        ("admin:tr0ub4dor", "Connect with postgres://admin:tr0ub4dor@db.internal:5432/main"),
    ],
)
def test_redacts_secret(secret, note):
    result = scrub(note)
    assert secret not in result.text
    assert REDACTION in result.text
    assert result.redactions


def test_keeps_the_key_name_and_drops_only_the_value():
    result = scrub("STRIPE_API_KEY=rk_live_8fJ2mQxZ4pLvN6tR\n")
    assert "STRIPE_API_KEY=" in result.text
    assert "rk_live" not in result.text


def test_keeps_the_host_and_drops_only_the_credentials():
    result = scrub("postgres://svc_billing:Xy7pQ2mNvL@db.internal:5432/payments")
    assert "db.internal:5432/payments" in result.text
    assert "Xy7pQ2mNvL" not in result.text


def test_reports_which_rule_fired():
    result = scrub("password=hunter2 and blob Zq3mK9vXpL2wRt7NcH4jB8sD6yF1aG5e")
    assert {r.rule for r in result.redactions} == {"assignment", "entropy"}


# --- false positives ----------------------------------------------------------

# Every line a genuinely useful handoff note would contain and a scrubber must
# leave alone. Breaking any of these makes C3 win by destroying the note.
CLEAN = [
    "Picked up the checkout refactor; the failing case is an empty basket.",
    "Renamed getUserById to findUserByIdentifier across the service layer.",
    'api_key = os.environ["PAYMENTS_API_KEY"]  # loaded at startup, never inlined',
    "const token = process.env.SESSION_TOKEN",
    "NEXT_PUBLIC_API_URL=https://api.example.com/v2",
    "Reverted 4c035fb because it broke the nightly job.",
    "See src/services/reconciliation_worker.py for the retry ladder.",
    "Config lives in ~/Library/Application Support/context-canary/settings.json",
    "AWS_REGION_US_EAST_1 is the only region wired up so far.",
    "The password field is still unvalidated; that is issue #41.",
    "Docs: https://docs.example.com/authentication/rotating-credentials",
    "TODO: set SESSION_SECRET=<your-value-here> before running locally.",
    "Timeout raised from 30 to 120 because uploads over 40MB were dying.",
]


@pytest.mark.parametrize("line", CLEAN)
def test_leaves_ordinary_note_content_alone(line):
    result = scrub(line)
    assert result.text == line
    assert result.clean


def test_a_whole_realistic_note_survives_untouched():
    note = "\n".join(CLEAN)
    assert scrub(note).text == note


# --- accepted false positive --------------------------------------------------


def test_full_git_sha_is_an_accepted_false_positive():
    """A 40-char hex SHA is shape-identical to a 160-bit hex secret.

    Rule 4 redacts it. Recorded here rather than special-cased: exempting
    40-char hex would open a hole a secret of that length walks straight through.
    Short SHAs, which is what notes actually quote, are untouched (see CLEAN).
    """
    result = scrub("Branched from 723524b0a1c94ef6d3b28e75f0ac41d9e6b8273c today.")
    assert REDACTION in result.text
    assert [r.rule for r in result.redactions] == ["entropy"]


# --- properties ---------------------------------------------------------------


def test_is_deterministic():
    note = "\n".join(CLEAN + ["password=hunter2", "key f47ac10b58cc4372a5670e02b2c3d479"])
    assert scrub(note).text == scrub(note).text


def test_is_idempotent():
    once = scrub("Rotate f47ac10b58cc4372a5670e02b2c3d479 and password=hunter2 now.")
    assert scrub(once.text).text == once.text


def test_redactions_carry_offsets_into_the_original():
    note = "Rotate f47ac10b58cc4372a5670e02b2c3d479 now."
    (redaction,) = scrub(note).redactions
    assert note[redaction.start : redaction.end] == redaction.text


@pytest.mark.parametrize(
    "token, floor, ceiling",
    [
        ("aaaaaaaaaaaaaaaa", 0.0, 0.1),
        ("f47ac10b58cc4372a5670e02b2c3d479", 3.5, 4.0),
        ("Zq3mK9vXpL2wRt7NcH4jB8sD6yF1aG5e", 4.5, 5.1),
    ],
)
def test_entropy_is_bits_per_character(token, floor, ceiling):
    assert floor <= entropy(token) <= ceiling
