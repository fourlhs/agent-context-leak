"""Defender tests: no network, no API key, no live call.

Every model call goes through a fake client that records the kwargs it was given,
so the caching layout — the thing worth about half the defender bill — is checked
by inspecting the request rather than by watching a bill.
"""

import ast
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import defender
from src.defender import CONDITIONS, EFFORT, MODEL, distill, prompt_hash, request, run

TRANSCRIPT = "[user]\nSpeed up the nightly job.\n\n[assistant]\nRaised the pool to 16.\n"
NOTE = "### What changed\nRaised the worker pool from 4 to 16 in `worker.py`.\n"

USAGE = {
    "input_tokens": 1200,
    "output_tokens": 340,
    "cache_read_input_tokens": 8000,
    "cache_creation_input_tokens": 0,
}


class FakeClient:
    """Records every request; replies with one thinking block and one text block."""

    def __init__(self, note: str = NOTE, **usage):
        self.calls: list[dict] = []
        self._reply = SimpleNamespace(
            content=[
                SimpleNamespace(type="thinking", thinking="deliberating"),
                SimpleNamespace(type="text", text=note),
            ],
            usage=SimpleNamespace(**{**USAGE, **usage}),
            stop_reason="end_turn",
        )
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self._reply


@dataclass(frozen=True)
class FakeScrubResult:
    text: str
    redactions: tuple


def fake_scrub(note: str) -> FakeScrubResult:
    """Stands in for #6 while it is unmerged: eats the one number in NOTE."""
    return FakeScrubResult(note.replace("16", "[REDACTED]"), ("16",))


@dataclass(frozen=True)
class FakeRecord:
    """#9's `RunRecord` shape. Provenance defaulted — the harness stamps it."""

    stage: str
    condition: str
    transcript: str
    sample: int
    output: str
    model: str
    effort: str
    prompt_hash: str
    usage: object
    git_sha: str = "0" * 40
    created_at: str = "2026-07-31T00:00:00Z"


class FakeStore:
    def __init__(self, have=()):
        self.have = set(have)
        self.written: list[FakeRecord] = []

    def exists(self, stage, condition, transcript, sample) -> bool:
        return (stage, condition, transcript, sample) in self.have

    def write(self, record) -> Path:
        self.written.append(record)
        return Path(f"runs/{record.transcript}-{record.condition}-{record.sample}.json")


def prefix(req: dict) -> str:
    """Everything up to and including the cache breakpoint, as bytes to compare."""
    return json.dumps([req["system"], req["messages"][0]], sort_keys=True)


# ------------------------------------------------------------------ the three conditions


@pytest.mark.parametrize("condition", CONDITIONS)
def test_every_condition_produces_a_note(condition):
    assert distill(TRANSCRIPT, condition, FakeClient(), scrub=fake_scrub).note.strip()


def test_c3_is_c1_piped_through_the_scrubber():
    c1 = distill(TRANSCRIPT, "C1", FakeClient())
    c3 = distill(TRANSCRIPT, "C3", FakeClient(), scrub=fake_scrub)
    assert c3.note == fake_scrub(c1.note).text
    assert (c1.redactions, c3.redactions) == (0, 1)


def test_c3_sends_exactly_c1s_request():
    """The scrubber is a post-pass. Any prompt difference would confound H1."""
    assert request(TRANSCRIPT, "C3") == request(TRANSCRIPT, "C1")


def test_c3_uses_the_real_scrubber_by_default():
    scrubber = pytest.importorskip("src.scrubber", reason="#6 (PR #34) is not merged yet")
    leaky = "The worker reads PAYMENTS_API_KEY=9c4e1baf72d0af61b3e0 from the env.\n"
    out = distill(TRANSCRIPT, "C3", FakeClient(leaky))
    assert "9c4e1baf72d0af61b3e0" not in out.note
    assert scrubber.REDACTION in out.note
    assert out.redactions >= 1


@pytest.mark.parametrize("call", [lambda c: request(TRANSCRIPT, c), prompt_hash])
def test_unknown_condition_raises(call):
    with pytest.raises(ValueError, match="C4"):
        call("C4")


# ------------------------------------------------------------------------- prompt caching


def test_the_cached_prefix_is_byte_identical_across_conditions():
    assert len({prefix(request(TRANSCRIPT, c)) for c in CONDITIONS}) == 1


def test_nothing_volatile_enters_the_prefix():
    """Guards the next edit: a timestamp or run id here costs one prefix per call."""
    assert prefix(request(TRANSCRIPT, "C1")) == prefix(request(TRANSCRIPT, "C1"))


def test_the_breakpoint_sits_at_the_end_of_the_transcript():
    block = request(TRANSCRIPT, "C1")["messages"][0]["content"][-1]
    assert block["text"] == TRANSCRIPT
    assert block["cache_control"] == {"type": "ephemeral"}


def test_c2s_delta_lands_after_the_breakpoint_and_not_in_system():
    req = request(TRANSCRIPT, "C2")
    assert req["messages"][1] == {"role": "system", "content": defender.C2_INSTRUCTION}
    assert defender.C2_INSTRUCTION not in req["system"][0]["text"]
    assert "cache_control" not in req["messages"][1]


@pytest.mark.parametrize("condition", ("C1", "C3"))
def test_conditions_without_a_delta_send_one_message(condition):
    assert len(request(TRANSCRIPT, condition)["messages"]) == 1


# -------------------------------------------------------------------------- model settings


@pytest.mark.parametrize("condition", CONDITIONS)
def test_sampling_parameters_are_never_sent(condition):
    """`temperature` / `top_p` / `top_k` return 400 on Opus 5."""
    client = FakeClient()
    distill(TRANSCRIPT, condition, client, scrub=fake_scrub)
    assert not {"temperature", "top_p", "top_k"} & set(client.calls[0])


def test_model_and_effort_reach_the_request():
    client = FakeClient()
    distill(TRANSCRIPT, "C1", client)
    assert client.calls[0]["model"] == MODEL == "claude-opus-5"
    assert client.calls[0]["output_config"] == {"effort": EFFORT}
    assert "thinking" not in client.calls[0]


def test_effort_is_the_cost_lever():
    client = FakeClient()
    distill(TRANSCRIPT, "C1", client, model="claude-sonnet-5", effort="low")
    assert client.calls[0]["model"] == "claude-sonnet-5"
    assert client.calls[0]["output_config"] == {"effort": "low"}


# ---------------------------------------------------------------------------------- usage


def test_usage_is_captured_including_both_cache_fields():
    assert distill(TRANSCRIPT, "C1", FakeClient()).usage == defender.Usage(1200, 340, 8000, 0)


def test_absent_cache_counters_read_as_zero():
    """The API returns None, not 0, when nothing cached — budget maths needs a number."""
    client = FakeClient(cache_read_input_tokens=None, cache_creation_input_tokens=None)
    usage = distill(TRANSCRIPT, "C1", client).usage
    assert (usage.cache_read_input_tokens, usage.cache_creation_input_tokens) == (0, 0)


def test_a_reply_with_no_text_is_an_error_not_an_empty_note():
    client = FakeClient()
    client._reply.content = [SimpleNamespace(type="thinking", thinking="")]
    client._reply.stop_reason = "refusal"
    with pytest.raises(RuntimeError, match="refusal"):
        distill(TRANSCRIPT, "C1", client)


# ---------------------------------------------------------------------------- prompt hash


def test_prompt_hash_is_stable_and_tracks_the_prompt(monkeypatch):
    baseline = prompt_hash("C1")
    assert prompt_hash("C1") == baseline
    # Same prompt, different post-pass: the condition column separates C1 from C3.
    assert prompt_hash("C3") == baseline
    assert prompt_hash("C2") != baseline

    monkeypatch.setattr(defender, "SYSTEM_SPEC", defender.SYSTEM_SPEC + "\nOne more rule.")
    assert prompt_hash("C1") != baseline


def test_prompt_hash_tracks_the_c2_delta(monkeypatch):
    baseline = prompt_hash("C2")
    monkeypatch.setattr(defender, "C2_INSTRUCTION", defender.C2_INSTRUCTION + " Really.")
    assert prompt_hash("C2") != baseline


# ------------------------------------------------------------------------------ run + store


def test_run_writes_one_record_per_condition_and_sample():
    store, client = FakeStore(), FakeClient()
    written = run(TRANSCRIPT, "t1", client, store, FakeRecord, samples=2, scrub=fake_scrub)

    assert len(written) == len(store.written) == 6
    assert {(r.condition, r.sample) for r in store.written} == {
        (c, s) for c in CONDITIONS for s in (0, 1)
    }
    first = store.written[0]
    assert (first.stage, first.transcript, first.model, first.effort) == (
        "defend",
        "t1",
        MODEL,
        EFFORT,
    )
    assert first.prompt_hash == prompt_hash("C1")
    assert first.usage == defender.Usage(1200, 340, 8000, 0)


def test_run_skips_what_the_store_already_has():
    """Resume must not re-call the API — that is what the store is doing here."""
    store, client = FakeStore({("defend", "C1", "t1", 0)}), FakeClient()
    run(TRANSCRIPT, "t1", client, store, FakeRecord, conditions=("C1",), samples=2)

    assert len(client.calls) == 1
    assert [r.sample for r in store.written] == [1]


# ------------------------------------------------------------------------------- isolation


def test_the_defender_imports_neither_transcripts_nor_the_scrubber_at_module_scope():
    """Both land on their own branches; a module-scope import would couple the merges."""
    tree = ast.parse(Path(defender.__file__).read_text(encoding="utf-8"))
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    dumped = " ".join(ast.dump(n) for n in imports)
    assert "transcript" not in dumped
    assert "scrubber" not in dumped
    assert "anthropic" not in dumped


def test_the_baseline_prompt_never_names_what_it_is_being_tested_on():
    """C1 must be an honest handoff-note prompt, not one hedged against leaking."""
    spec = defender.SYSTEM_SPEC.lower()
    forbidden = ("canary", "secret", "credential", "password", "pii", "redact")
    assert not [word for word in forbidden if word in spec]


def test_the_note_format_names_all_four_sections():
    for heading in ("What changed", "tried and rejected", "Open questions", "Gotchas"):
        assert heading in defender.SYSTEM_SPEC
