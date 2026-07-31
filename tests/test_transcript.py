"""Tests for the transcript schema, and for the two committed pilots.

The exposure tests are the point of the file. `exposes` is the denominator for
every per-category rate in #13, and a wrong denominator does not look wrong in
the output — so it is checked against the rendered text in both directions
rather than taken on trust.
"""

import json

import pytest

from scripts.build_fixture import build
from src.manifest import load as load_manifest
from src.transcript import DEFAULT_DIR, Transcript, Turn, load, load_all, validate

MANIFEST = load_manifest()
BY_ID = {c.id: c for c in MANIFEST}


def write(tmp_path, **overrides):
    raw = {
        "id": "t99_synthetic",
        "summary": "A short synthetic session.",
        "exposes": [],
        "turns": [
            {"role": "user", "text": "have a look at the read path"},
            {"role": "assistant", "text": "Starting in db.py."},
        ],
        **overrides,
    }
    path = tmp_path / f"{raw['id']}.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def surfacing(canary_id):
    """A turn whose text contains that canary, as a tool result would."""
    return {"role": "tool_call", "tool": "bash", "text": "cat .env"}, {
        "role": "tool_result",
        "tool": "bash",
        "text": BY_ID[canary_id].context,
    }


# --- the committed pilots -----------------------------------------------------


def test_every_committed_pilot_loads_and_validates():
    transcripts = load_all(MANIFEST)
    assert len(transcripts) == 2


def test_pilots_expose_different_canary_sets():
    """Otherwise the pilot gate never exercises an exposure-conditioned denominator."""
    sets = [frozenset(t.exposes) for t in load_all(MANIFEST)]
    assert len(set(sets)) == len(sets)
    assert all(sets)


def test_pilots_are_messy_enough_to_be_representative():
    """A clean linear success story understates leakage — see #7."""
    for transcript in load_all(MANIFEST):
        roles = [t.role for t in transcript.turns]
        assert roles.count("user") >= 2, f"{transcript.id}: no operator interjection"
        assert len(transcript.turns) >= 20, f"{transcript.id}: too short to be a session"


@pytest.mark.parametrize("transcript", load_all(MANIFEST), ids=lambda t: t.id)
def test_quoted_files_match_the_fixture(transcript, tmp_path):
    """A transcript quoting a file that has since changed is a broken transcript."""
    build(tmp_path)
    for turn in transcript.turns:
        if not turn.file:
            continue
        actual = (tmp_path / turn.file).read_text(encoding="utf-8")
        assert turn.text.strip() in actual, f"{transcript.id} misquotes {turn.file}"


# --- exposure -----------------------------------------------------------------


def test_declaring_a_canary_the_text_never_surfaces_is_rejected(tmp_path):
    path = write(tmp_path, exposes=["env_secret_01"])
    with pytest.raises(ValueError, match="never surfaces it"):
        load(path, MANIFEST)


def test_surfacing_a_canary_without_declaring_it_is_rejected(tmp_path):
    """The direction that matters: an undeclared leak the aggregation cannot count."""
    call, result = surfacing("env_secret_01")
    path = write(tmp_path, turns=[{"role": "user", "text": "check config"}, call, result])
    with pytest.raises(ValueError, match="without declaring it"):
        load(path, MANIFEST)


def test_declared_and_surfaced_agree(tmp_path):
    call, result = surfacing("env_secret_01")
    path = write(
        tmp_path,
        exposes=["env_secret_01"],
        turns=[{"role": "user", "text": "check config"}, call, result],
    )
    assert load(path, MANIFEST).exposes == ("env_secret_01",)


@pytest.mark.parametrize(
    "exposes, expected",
    [
        (["no_such_canary"], "unknown canary"),
        (["env_secret_01", "env_secret_01"], "duplicate id in exposes"),
    ],
)
def test_rejects_bad_exposure_list(tmp_path, exposes, expected):
    with pytest.raises(ValueError, match=expected):
        load(write(tmp_path, exposes=exposes), MANIFEST)


# --- schema -------------------------------------------------------------------


def test_id_must_match_filename(tmp_path):
    path = write(tmp_path)
    renamed = path.with_name("t98_other.json")
    path.rename(renamed)
    with pytest.raises(ValueError, match="does not match filename"):
        load(renamed, MANIFEST)


@pytest.mark.parametrize(
    "turns, expected",
    [
        ([], "no turns"),
        ([{"role": "assistant", "text": "hi"}], "first turn must be user"),
        ([{"role": "user", "text": "x"}, {"role": "narrator", "text": "y"}], "unknown role"),
        ([{"role": "user", "text": "  "}], "empty text"),
        (
            [{"role": "user", "text": "x"}, {"role": "tool_result", "tool": "bash", "text": "y"}],
            "has no matching call",
        ),
        (
            [{"role": "user", "text": "x"}, {"role": "tool_call", "tool": "bash", "text": "ls"}],
            "has no result",
        ),
        (
            [
                {"role": "user", "text": "x"},
                {"role": "tool_call", "tool": "bash", "text": "ls"},
                {"role": "tool_result", "tool": "read_file", "text": "y"},
            ],
            "has no matching call",
        ),
        (
            [{"role": "user", "text": "x", "tool": "bash"}],
            "cannot carry tool/file",
        ),
    ],
)
def test_rejects_malformed_turns(tmp_path, turns, expected):
    with pytest.raises(ValueError, match=expected):
        load(write(tmp_path, turns=turns), MANIFEST)


def test_rejects_unexpected_field(tmp_path):
    with pytest.raises(ValueError, match="unexpected"):
        load(write(tmp_path, model="claude-opus-5"), MANIFEST)


def test_rejects_empty_summary(tmp_path):
    with pytest.raises(ValueError, match="empty summary"):
        load(write(tmp_path, summary="   "), MANIFEST)


# --- render -------------------------------------------------------------------


def test_render_is_the_shared_definition_of_the_session_text():
    transcript = Transcript(
        id="t97",
        summary="s",
        exposes=(),
        turns=(
            Turn("user", "why is it slow"),
            Turn("assistant", "Reading db.py."),
            Turn("tool_call", "db.py", tool="read_file"),
            Turn("tool_result", "BACKOFF_SECONDS = 0.25", tool="read_file", file="db.py"),
        ),
    )
    assert transcript.render() == (
        "[user]\nwhy is it slow\n\n"
        "[assistant]\nReading db.py.\n\n"
        "[read_file] db.py\n\n"
        "[read_file → result]\nBACKOFF_SECONDS = 0.25\n"
    )


def test_render_is_deterministic():
    (transcript,) = load_all(MANIFEST, DEFAULT_DIR)[:1]
    assert transcript.render() == transcript.render()


def test_validate_accepts_a_transcript_with_no_exposure():
    """Legitimate: a session that never surfaces a canary is still a valid input."""
    validate(
        Transcript("t96", "s", (), (Turn("user", "x"), Turn("assistant", "y"))),
        MANIFEST,
    )
