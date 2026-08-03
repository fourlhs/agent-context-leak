"""Defender tests: no network, no API key, no live call.

Every model call goes through a fake client that records the kwargs it was given,
so the caching layout — the thing worth about half the defender bill — is checked
by inspecting the request rather than by watching a bill.
"""

import ast
import json
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import defender
from src.defender import CONDITIONS, EFFORT, MODEL, distill, prompt_hash, request, run
from src.runs import RunStore, Usage

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


@pytest.fixture
def store(tmp_path) -> RunStore:
    """The real store, on a temp root. No fake: a hand-mirrored record agrees
    today and drifts later, and the drift is invisible until the pilot gate."""
    return RunStore(tmp_path)


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
    # `src.runs.Usage`, not a local twin: a dataclass `__eq__` across two
    # different classes falls back to identity and is silently never equal.
    assert distill(TRANSCRIPT, "C1", FakeClient()).usage == Usage(1200, 340, 8000, 0)


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


# ------------------------------------------------------------------------------ truncation


@pytest.mark.parametrize("condition", CONDITIONS)
def test_a_truncated_note_is_never_returned_as_a_complete_one(condition):
    """The dangerous case: a partial note looks complete and scores low on every tier.

    Thinking bills against `max_tokens`, so this is live. Silently returning it
    would put a near-zero numerator against a denominator that counts the sample
    anyway — the headline biased downward with nothing in `runs/` to show it.
    """
    client = FakeClient("### What changed\nRaised the worker pool from 4 to 1")
    client._reply.stop_reason = "max_tokens"
    with pytest.raises(RuntimeError, match="truncated"):
        distill(TRANSCRIPT, condition, client, scrub=fake_scrub)


def test_a_truncated_note_never_reaches_the_store(store):
    client = FakeClient()
    client._reply.stop_reason = "max_tokens"
    with pytest.raises(RuntimeError, match="truncated"):
        run(TRANSCRIPT, "t1", client, store, samples=1, **PROVENANCE)
    assert store.read_all() == ()


# ------------------------------------------------------------- refusal vs truncation


def refusing(client):
    """A reply in Opus 5's documented refusal shape: HTTP 200, empty content."""
    client._reply.content = [SimpleNamespace(type="thinking", thinking="")]
    client._reply.stop_reason = "refusal"
    return client


def test_a_refusal_and_a_truncation_are_different_exceptions():
    """They arrive from the same function and used to be the same class, so a
    caller could not survive one and stop on the other. #14 must do exactly that:
    a refusal costs one sample, a truncation says `MAX_TOKENS` is wrong for the
    corpus and every further call is spend against a broken ceiling.
    """
    truncating = FakeClient()
    truncating._reply.stop_reason = "max_tokens"

    with pytest.raises(defender.Refused):
        distill(TRANSCRIPT, "C1", refusing(FakeClient()))
    with pytest.raises(defender.Truncated):
        distill(TRANSCRIPT, "C1", truncating)
    # Both still `RuntimeError`, so an existing caller catching that is unaffected.
    assert issubclass(defender.Refused, RuntimeError)
    assert issubclass(defender.Truncated, RuntimeError)
    assert not issubclass(defender.Refused, defender.Truncated)


def test_a_refusal_carries_what_the_call_billed():
    """The call happened either way, and #14 multiplies measured spend. A refusal
    that drops its tokens is spend the budget check cannot see."""
    with pytest.raises(defender.Refused) as raised:
        distill(TRANSCRIPT, "C1", refusing(FakeClient()))

    assert raised.value.usage == Usage(1200, 340, 8000, 0)
    assert raised.value.stop_reason == "refusal"


def test_a_refusal_is_logged_and_re_raised_by_default(store):
    """Log first, then raise. The default stays loud — only #14 opts out."""
    with pytest.raises(defender.Refused):
        run(TRANSCRIPT, "t1", refusing(FakeClient()), store, samples=1, **PROVENANCE)

    record = store.read(defender.STAGE, "C1", "t1", 0)
    assert defender.failed(record)
    assert record.usage == Usage(1200, 340, 8000, 0)
    assert record.stop_reason == "refusal"


def test_a_failure_record_cannot_be_read_as_an_empty_note(store):
    """No note in it at all. Scored as one it would find no canary, read clean,
    and sit in every exposure-conditioned denominator anyway."""
    with pytest.raises(defender.Refused):
        run(TRANSCRIPT, "t1", refusing(FakeClient()), store, samples=1, **PROVENANCE)

    record = store.read(defender.STAGE, "C1", "t1", 0)
    assert json.loads(record.output)["failed"]
    assert record.raw_output == ""
    # And the predicate is not vacuous: a real note is not a failure.
    assert not defender.failed(replace(record, output=NOTE))


def test_a_collector_lets_one_caller_survive_a_refusal(store):
    """`on_refusal` is a parameter for exactly one caller, on the precedent
    `attacker.run`'s `stage` sets. #14 must not abort on a refused note — it has
    already spent the money and would report nothing."""
    collected = []
    run(
        TRANSCRIPT,
        "t1",
        refusing(FakeClient()),
        store,
        samples=2,
        on_refusal=lambda c, s, exc: collected.append((c, s, str(exc))),
        **PROVENANCE,
    )

    assert len(collected) == len(CONDITIONS) * 2  # the loop carried on to the end
    assert len(store.read_all()) == len(CONDITIONS) * 2
    assert all(defender.failed(r) for r in store.read_all())


def test_a_truncation_propagates_even_with_a_collector(store):
    """The carve-out is refusals only. A truncated note biases every tier
    downward while looking complete, and the ceiling is wrong for the whole run."""
    client = FakeClient()
    client._reply.stop_reason = "max_tokens"

    with pytest.raises(defender.Truncated):
        run(
            TRANSCRIPT,
            "t1",
            client,
            store,
            samples=1,
            on_refusal=lambda *a: pytest.fail("a truncation must not be collected"),
            **PROVENANCE,
        )


def test_a_good_record_carries_its_stop_reason(store):
    """Computed in `Distillation` and, before #14, thrown away."""
    run(TRANSCRIPT, "t1", FakeClient(), store, conditions=("C1",), samples=1, **PROVENANCE)

    assert store.read(defender.STAGE, "C1", "t1", 0).stop_reason == "end_turn"


def test_stop_reason_leaves_distill_so_it_can_be_acted_on():
    assert distill(TRANSCRIPT, "C1", FakeClient()).stop_reason == "end_turn"
    assert distill(TRANSCRIPT, "C3", FakeClient(), scrub=fake_scrub).stop_reason == "end_turn"


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


PROVENANCE = {"git_sha": "0" * 40, "created_at": "2026-07-31T00:00:00Z"}


def test_run_writes_one_record_per_condition_and_sample(store):
    client = FakeClient()
    written = run(TRANSCRIPT, "t1", client, store, samples=2, scrub=fake_scrub, **PROVENANCE)
    records = store.read_all()

    assert len(written) == len(records) == 6
    assert {(r.condition, r.sample) for r in records} == {
        (c, s) for c in CONDITIONS for s in (0, 1)
    }
    first = store.read(defender.STAGE, "C1", "t1", 0)
    assert (first.stage, first.transcript, first.model, first.effort) == (
        "defender",
        "t1",
        MODEL,
        EFFORT,
    )
    assert first.prompt_hash == prompt_hash("C1")
    assert first.usage == Usage(1200, 340, 8000, 0)
    assert (first.git_sha, first.created_at) == (PROVENANCE["git_sha"], PROVENANCE["created_at"])


def test_the_stage_matches_the_harnesss_vocabulary():
    """`runs_report.summarise()` groups on it; "defend" would KeyError at #14."""
    assert defender.STAGE == "defender"


def test_c3s_raw_generation_survives_the_round_trip(store):
    """Read back off disk, not off the object we just built.

    Without `raw_output` the scrubber's input is gone and retuning its entropy
    threshold costs 90 defender calls.
    """
    run(TRANSCRIPT, "t1", FakeClient(), store, samples=1, scrub=fake_scrub, **PROVENANCE)
    c3 = store.read(defender.STAGE, "C3", "t1", 0)

    assert c3.raw_output == NOTE.strip()
    assert c3.output == fake_scrub(NOTE.strip()).text
    assert c3.output != c3.raw_output
    # `output` is what the attacker sees, so an unscrubbed C3 note must not be it.
    assert "16" not in c3.output


@pytest.mark.parametrize("condition", ("C1", "C2"))
def test_conditions_without_a_scrubber_leave_raw_output_empty(store, condition):
    """`output` already is the raw generation; storing it twice buys nothing."""
    run(
        TRANSCRIPT,
        "t1",
        FakeClient(),
        store,
        conditions=(condition,),
        samples=1,
        **PROVENANCE,
    )
    record = store.read(defender.STAGE, condition, "t1", 0)
    assert record.raw_output == ""
    assert record.output == NOTE.strip()


def test_run_skips_what_the_store_already_has(store):
    """Resume must not re-call the API — that is what the store is doing here."""
    client = FakeClient()
    run(TRANSCRIPT, "t1", client, store, conditions=("C1",), samples=1, **PROVENANCE)
    run(TRANSCRIPT, "t1", client, store, conditions=("C1",), samples=2, **PROVENANCE)

    # Two calls, not three: sample 0 was already on disk the second time around.
    assert len(client.calls) == 2
    assert sorted(r.sample for r in store.read_all()) == [0, 1]


# ------------------------------------------------------------------------------- isolation


def test_the_defender_imports_neither_transcripts_nor_the_scrubber_at_module_scope():
    """Three different reasons, one assertion.

    `transcript` — `distill` takes rendered text, so the defender needs no
    fixture and no manifest to be exercised. `scrubber` — #34 is still on its own
    branch. `anthropic` — the deterministic tests must never need the SDK
    installed to import this module.
    """
    tree = ast.parse(Path(defender.__file__).read_text(encoding="utf-8"))
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    dumped = " ".join(ast.dump(n) for n in imports)
    assert "transcript" not in dumped
    assert "scrubber" not in dumped
    assert "anthropic" not in dumped


def test_the_defender_uses_the_stores_own_usage_class():
    """A local twin would compare unequal to a record read back from `runs/`,
    silently, at exactly the budget reconciliation the pilot gate performs."""
    assert defender.Usage is Usage


def test_the_baseline_prompt_never_names_what_it_is_being_tested_on():
    """C1 must be an honest handoff-note prompt, not one hedged against leaking."""
    spec = defender.SYSTEM_SPEC.lower()
    forbidden = ("canary", "secret", "credential", "password", "pii", "redact")
    assert not [word for word in forbidden if word in spec]


def test_the_note_format_names_all_four_sections():
    for heading in ("What changed", "tried and rejected", "Open questions", "Gotchas"):
        assert heading in defender.SYSTEM_SPEC
