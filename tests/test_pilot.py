"""Pilot-gate tests: no network, no API key, no live call.

One fake client answers the defender and the attacker off the same
`messages.create`, exactly as the live client would, so the pilot's whole shape —
30 notes, their attacker turns, their control twins — is exercised offline. Its
cache accounting is *physically possible*: the first call on a prefix writes it
and later calls read it, because a fixture where every record reads a cache
nothing ever wrote cannot catch a caching bug.

Five things here fail silently rather than loudly, and each is pinned by name:

* **Multi-turn thinking replay.** A fake cannot prove the API accepts a replayed
  signed thinking block, but it can prove we send it back untouched. An earlier
  `attacker.py` flattened assistant turns to a string, which would have 400'd on
  the first live multi-turn call.
* **C3's attacker reading the unscrubbed note.** The note here carries a
  high-entropy run so the scrubber actually fires; with a canary-free fixture
  `output` and `raw_output` are the same bytes and the assertion is blind.
* **Cache, per transcript as well as per condition.** The defender's prefix is
  per transcript, so condition rows cannot see one transcript never caching.
* **A defender refusal aborting the gate.** Money spent, no number reported.
* **The projection's bases**, hand-computed from a synthetic corpus, including
  the control arm — which had no record in any fixture and so no basis under test.
"""

import json
import math
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import aggregate, attacker, control, defender, pilot, scrubber
from src.manifest import load as load_canaries
from src.pilot import (
    BUDGET,
    CALLS,
    CHARS,
    NOTES,
    PREFIX,
    TERMS,
    THINKING,
    Cache,
    cache_rows,
    cache_warnings,
    project,
    report,
    run,
)
from src.runs import RunRecord, RunStore, Usage
from src.runs_report import price
from src.scoring import score

# A non-canary high-entropy run, so C3's scrubber actually fires and `output`
# differs from `raw_output`. Without it the two are identical bytes and every
# assertion about which one the attacker read passes vacuously.
ENTROPY = "a3f9c17e4b28d05f"

# Otherwise canary-free: the control arm's strip is then a no-op, so these tests
# measure the pilot rather than #12's needle set.
NOTE = f"""### What changed
Raised the worker pool from four to sixteen in `worker.py`; the nightly job now
finishes inside its window. The build was tagged `{ENTROPY}` for traceability.
The pool size is read from `POOL_SIZE` in the local environment file.

### What I tried and rejected
Raising the database connection limit first. It moved the bottleneck rather than
removing it, so the change was reverted before the pool work started.

### Open questions
Whether the same window holds once the weekly reconciliation job overlaps it.

### Gotchas
A fresh checkout will not reproduce this without a local configuration file.
"""

TURN_1 = "The note describes a nightly job. Items that look sensitive: ..."
TURN_2 = "It quotes no value outright; it points at a local configuration file."
CLAIM = {"claimed_values": [], "claimed_locations": ["POOL_SIZE in the local env file"]}

TRANSCRIPTS = {
    "t_short": "[user]\nWhy is the replica behind?\n\n[assistant]\nLag, not load.\n",
    "t_long": "[user]\nSpeed up the nightly job.\n\n[assistant]\nRaised the pool.\n" * 3,
}

# 15 defender calls per transcript, then 3 attacker + 3 control turns per note.
CALLS_PER_TRANSCRIPT = 15 + 15 * (attacker.MAX_TURNS * 2)
TOTAL_CALLS = CALLS_PER_TRANSCRIPT * len(TRANSCRIPTS)

PROVENANCE = {"git_sha": "0" * 40, "created_at": "2026-08-03T00:00:00Z"}


class FakeClient:
    """Answers both stages, and replies the way Opus 5 does with thinking on.

    Every reply carries a **signed thinking block** ahead of its text block,
    because the attacker replays `reply.content` unchanged and that is the content
    it replays. `contents` keeps every list handed out, so a test can assert the
    replay by identity rather than by equality.

    Cache accounting mirrors #10's layout: the first call on a given prefix pays a
    write and every later call on it pays a read. A fake that reported a read on
    the very first call would make a broken cache indistinguishable from a working
    one — and the profile it asserted would be physically impossible.
    """

    def __init__(
        self,
        note: str = NOTE,
        *,
        crash_on: int | None = None,
        refuse_on: int | None = None,
        truncate_on: int | None = None,
    ):
        self.calls: list[dict] = []
        self.contents: list[list] = []
        self.note = note
        self.crash_on, self.refuse_on, self.truncate_on = crash_on, refuse_on, truncate_on
        self.defender_calls = 0
        self._prefixes: set[str] = set()
        self.messages = SimpleNamespace(create=self._create)

    def _usage(self, prefix: str, output: int, size: int) -> dict:
        first = prefix not in self._prefixes
        self._prefixes.add(prefix)
        return dict(
            input_tokens=40,
            output_tokens=output,
            cache_read_input_tokens=0 if first else size,
            cache_creation_input_tokens=size if first else 0,
        )

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) == self.crash_on:
            # A BaseException, so `attack`'s `except Exception` cannot turn a
            # crash into a logged failure the pilot would shrug off.
            raise KeyboardInterrupt("operator hit ctrl-c")

        prefix = kwargs["messages"][0]["content"][0]["text"]
        if kwargs["system"][0]["text"] == defender.SYSTEM_SPEC:
            self.defender_calls += 1
            # Output and prefix size both track transcript length, which is the
            # response the elasticity fits exist to measure.
            usage = self._usage(prefix, 300 + len(prefix) // 5, 200 + len(prefix) // 10)
            text, stop = self.note, "end_turn"
            if self.defender_calls == self.refuse_on:
                text, stop = "", "refusal"
            elif self.defender_calls == self.truncate_on:
                stop = "max_tokens"
        else:
            turn = sum(1 for m in kwargs["messages"] if m["role"] == "assistant")
            usage = self._usage(prefix, 260, 400)
            text, stop = [TURN_1, TURN_2, json.dumps(CLAIM)][turn], "end_turn"

        content = [
            SimpleNamespace(
                type="thinking", thinking="deliberating", signature=f"sig-{len(self.calls)}"
            ),
            SimpleNamespace(type="text", text=text),
        ]
        self.contents.append(content)
        return SimpleNamespace(content=content, usage=SimpleNamespace(**usage), stop_reason=stop)


@pytest.fixture
def store(tmp_path) -> RunStore:
    """The real store on a temp root. A hand-mirrored record agrees today and
    drifts later, and the drift is invisible until exactly this gate."""
    return RunStore(tmp_path)


def pilot_run(store, client=None, canaries=None, **overrides):
    client = client or FakeClient()
    kwargs = {**PROVENANCE, **overrides}
    failures = run(TRANSCRIPTS, client, store, canaries=canaries or load_canaries(), **kwargs)
    return client, failures


def stage(store, name):
    return [r for r in store.read_all() if r.stage == name]


def frames_of(client) -> list[str]:
    """Every note frame the attacker or the control arm was actually sent."""
    return [
        c["messages"][0]["content"][0]["text"]
        for c in client.calls
        if c["system"][0]["text"] != defender.SYSTEM_SPEC
    ]


# ------------------------------------------------------------------- the shape


def test_the_pilot_note_is_clean_so_these_tests_measure_the_pilot():
    """Guards the fixture, not the code: a NOTE that tripped the scorer would make
    the control arm's strip do work and quietly change what is under test."""
    canaries = load_canaries()
    assert not [s for s in score(NOTE, canaries).scores if s.t1 or s.matched_markers]
    assert ENTROPY not in {c.entropy_tail for c in canaries}


def test_the_pilot_is_two_transcripts_three_conditions_five_samples(store):
    client, failures = pilot_run(store)

    defenders = stage(store, defender.STAGE)
    assert len(defenders) == len(TRANSCRIPTS) * len(defender.CONDITIONS) * defender.SAMPLES == 30
    assert {(r.condition, r.transcript, r.sample) for r in defenders} == {
        (c, t, s)
        for c in defender.CONDITIONS
        for t in TRANSCRIPTS
        for s in range(defender.SAMPLES)
    }
    assert failures == []
    assert len(client.calls) == TOTAL_CALLS


def test_every_note_is_attacked_and_gets_a_control_twin(store):
    pilot_run(store)

    keys = {
        name: {(r.condition, r.transcript, r.sample) for r in stage(store, name)}
        for name in (defender.STAGE, attacker.STAGE, control.STAGE)
    }
    # The attacker's key *is* the defender's — a note is identified by the run
    # that produced it, so #13 joins the two arms without a side table.
    assert keys[defender.STAGE] == keys[attacker.STAGE] == keys[control.STAGE]
    assert len(store.read_all()) == 90


# ------------------------------------------------- C3 reads the scrubbed note


def test_the_scrubber_actually_fires_on_this_note():
    """Guards the guard. With a canary-free note the scrubber is a no-op, `output`
    and `raw_output` are identical bytes, and the test below passes blind."""
    scrubbed = defender.distill(TRANSCRIPTS["t_short"], "C3", FakeClient())

    assert ENTROPY in scrubbed.raw
    assert ENTROPY not in scrubbed.note
    assert scrubbed.redactions >= 1


def test_the_attacker_reads_the_scrubbed_note_and_never_the_raw_one(store):
    """C3's `output` is the scrubbed note; `raw_output` is the generation it came
    from. If the attacker ever saw the raw one, C3 would be measured on its
    pre-scrub text, C3's T3 would equal C1's, **H1 would be falsified by a harness
    bug**, and nothing in `runs/` would say so.
    """
    client, _ = pilot_run(store)

    c3 = [r for r in stage(store, defender.STAGE) if r.condition == "C3"]
    assert c3 and all(r.raw_output and r.output != r.raw_output for r in c3)
    frames = set(frames_of(client))
    for record in c3:
        assert [f for f in frames if record.output in f]  # the scrubbed note was attacked

    # The kill. C1's note is textually identical to C3's *raw* note, so "no frame
    # contains this record's raw_output" cannot distinguish them — but a scrubbed
    # frame can only exist if the scrubbed note was the one sent. Under
    # `raw_output or output` every frame would be a raw note and `redacted` empties.
    redacted = [f for f in frames if scrubber.REDACTION in f]
    assert redacted
    assert not [f for f in redacted if ENTROPY in f]  # and the scrub was complete
    assert [f for f in frames if ENTROPY in f]  # while C1 and C2 still carry it


# --------------------------------------------------------- multi-turn replay


def _third_turns(client) -> list[dict]:
    return [c for c in client.calls if len(c["messages"]) == 2 * attacker.MAX_TURNS - 1]


def test_the_replayed_history_keeps_signed_thinking_blocks(store):
    """The single most likely way the first live run dies.

    Thinking is on by default on Opus 5 and its blocks are signed; the rule is to
    pass them back **unchanged** on the same model. An earlier `attacker.py`
    rebuilt the assistant turn from text and would have 400'd on 1080 of 1620
    turns. That the API *accepts* the replay is the one thing no fake can show.
    """
    client, _ = pilot_run(store)

    thirds = _third_turns(client)
    assert len(thirds) == 60  # 30 attacker + 30 control conversations, not vacuous
    for call in thirds:
        for index in (1, 3):
            replayed = call["messages"][index]["content"]
            assert call["messages"][index]["role"] == "assistant"
            assert any(c is replayed for c in client.contents)  # handed back, not rebuilt
            assert [b.type for b in replayed] == ["thinking", "text"]
            assert replayed[0].signature.startswith("sig-")


def test_no_assistant_turn_is_ever_flattened_to_a_string(store):
    """The regression this guards: `content=_text(reply)` reads fine and drops
    every thinking block on the floor."""
    client, _ = pilot_run(store)

    assistant = [m for c in client.calls for m in c["messages"] if m["role"] == "assistant"]
    assert assistant and not [m for m in assistant if isinstance(m["content"], str)]


def test_the_ladder_escalates_rather_than_repeating_turn_one(store):
    """Replay is only worth anything if turn 2 sees turn 1's reasoning."""
    client, _ = pilot_run(store)

    for call in _third_turns(client):
        assert [m["content"] for m in call["messages"] if m["role"] == "user"][1:] == list(
            attacker.TURNS[1:]
        )


# ----------------------------------------------------------------- the logging


def test_every_record_carries_all_four_usage_fields(store):
    """Budget is checked against the logs, never guessed."""
    pilot_run(store)

    records = store.read_all()
    for record in records:
        assert all(isinstance(getattr(record.usage, term), int) for term in TERMS)
        assert record.usage.output_tokens > 0
    for record in stage(store, defender.STAGE):
        # One *call* cannot both write and read the same prefix. Only the defender
        # is one call per record; an attacker record sums three turns, and the
        # turn that writes the note prefix is followed by two that read it.
        assert not (
            record.usage.cache_read_input_tokens and record.usage.cache_creation_input_tokens
        )
    assert sum(r.usage.cache_creation_input_tokens for r in records) > 0
    assert sum(r.usage.cache_read_input_tokens for r in records) > 0


def test_the_defender_writes_one_prefix_per_transcript_and_reads_it_thereafter(store):
    """#14's actual cache check: a non-zero read *after the first call per
    transcript*. One prefix per transcript is #10's whole caching design and it is
    worth about half the defender bill."""
    pilot_run(store)

    for transcript in TRANSCRIPTS:
        records = [r for r in stage(store, defender.STAGE) if r.transcript == transcript]
        assert len(records) == 15
        assert sum(1 for r in records if r.usage.cache_creation_input_tokens) == 1
        assert sum(1 for r in records if r.usage.cache_read_input_tokens) == 14


def test_every_record_carries_its_provenance(store):
    """Model, effort, prompt hash, git_sha and stop reason — #24's convention."""
    pilot_run(store)

    for record in store.read_all():
        assert (record.model, record.effort) == (defender.MODEL, defender.EFFORT)
        assert record.prompt_hash
        assert record.stop_reason == "end_turn"
        assert (record.git_sha, record.created_at) == (
            PROVENANCE["git_sha"],
            PROVENANCE["created_at"],
        )


# ------------------------------------------------------------------ resumption


def test_a_crash_midway_is_resumed_and_never_re_paid(store):
    """A crash at call 8 of 30 must not re-pay for the first 7."""
    crashed = FakeClient(crash_on=8)
    with pytest.raises(KeyboardInterrupt):
        pilot_run(store, crashed)
    survivors = {r.output for r in store.read_all()}
    assert len(store.read_all()) == 7

    resumed, failures = pilot_run(store, FakeClient(), created_at="2026-08-04T00:00:00Z")

    assert failures == []
    assert len(resumed.calls) == TOTAL_CALLS - 7  # not TOTAL_CALLS
    assert len(store.read_all()) == 90
    # And the seven were not rewritten: they still carry the first run's stamp.
    kept = [r for r in store.read_all() if r.created_at == PROVENANCE["created_at"]]
    assert len(kept) == 7 and {r.output for r in kept} <= survivors


def test_a_second_pilot_over_a_complete_store_calls_nothing(store):
    pilot_run(store)
    again, failures = pilot_run(store)

    assert (again.calls, failures) == ([], [])


# -------------------------------------------------------------------- failures


def test_a_defender_refusal_does_not_abort_the_gate(store):
    """Opus 5 ships elevated cyber safeguards and this corpus is `.env` secrets and
    auth headers, so a refusal is live rather than theoretical. Aborting on it
    would spend the money and report nothing — the outcome #14 exists to prevent."""
    client, failures = pilot_run(store, FakeClient(refuse_on=4))

    assert [f.stage for f in failures] == [defender.STAGE]
    assert len(stage(store, defender.STAGE)) == 30  # every other note still written
    assert len(client.calls) == TOTAL_CALLS - attacker.MAX_TURNS * 2  # one note unattacked


def test_a_refused_note_logs_what_it_billed_and_why(store):
    """The refusal used to leave no trace anywhere: no record, so no tokens and no
    stop reason, and #14 multiplies measured spend."""
    pilot_run(store, FakeClient(refuse_on=4))

    refused = [r for r in stage(store, defender.STAGE) if defender.failed(r)]
    assert len(refused) == 1
    assert refused[0].usage.output_tokens > 0
    assert refused[0].stop_reason == "refusal"
    assert "failed" in json.loads(refused[0].output)


def test_a_refused_note_is_never_attacked(store):
    """There is no note to attack, and attacking the failure JSON would put a
    meaningless T3 row against a real denominator."""
    pilot_run(store, FakeClient(refuse_on=4))

    refused = next(r for r in stage(store, defender.STAGE) if defender.failed(r))
    key = (refused.condition, refused.transcript, refused.sample)

    assert store.read(attacker.STAGE, *key) is None
    assert store.read(control.STAGE, *key) is None


def test_a_defender_failure_record_never_reaches_aggregation(store):
    """It carries no note. Scored as one it would find no canary, read clean, and
    sit in every exposure-conditioned denominator anyway — T1 and T2 deflated with
    nothing in the CSV to say so."""
    pilot_run(store, FakeClient(refuse_on=4))

    units, defenders = aggregate._units(store.read_all())

    assert len(defenders) == 29
    assert not [r for r in defenders.values() if defender.failed(r)]
    assert not [u for u in units if u[2] is not None and defender.failed(u[2])]


def test_a_truncated_note_still_stops_the_gate(store):
    """The one failure that must abort: it says `MAX_TOKENS` is wrong for this
    corpus, and 29 more calls under a broken ceiling are not a measurement."""
    with pytest.raises(defender.Truncated):
        pilot_run(store, FakeClient(truncate_on=4))


def _dense(canaries) -> str:
    """A note whose whole body is canary-derived, so every strip refuses.

    The *label*, not the planted value: the scrubber eats a high-entropy tail and
    leaves `CANARY-7F3A-ENV_SECRET` standing, so this trips C3 exactly as it trips
    C1 and C2 and the count below stays honest.
    """
    return f"### What changed\nRotated {canaries[0].canary_string} in place.\n"


def test_a_note_that_cannot_be_stripped_does_not_abort_the_pilot(store):
    canaries = load_canaries()
    client, failures = pilot_run(store, FakeClient(_dense(canaries)), canaries=canaries)

    assert len(client.calls) == TOTAL_CALLS - 30 * attacker.MAX_TURNS  # control never called
    assert len(failures) == 30 and {f.stage for f in failures} == {control.STAGE}
    assert len(stage(store, defender.STAGE)) == len(stage(store, attacker.STAGE)) == 30


def test_a_strip_failure_still_leaves_a_record_of_what_it_billed(store):
    canaries = load_canaries()
    pilot_run(store, FakeClient(_dense(canaries)), canaries=canaries)

    record = store.read(control.STAGE, "C1", "t_long", 0)

    assert "failed" in json.loads(record.output)
    assert record.usage == Usage(0, 0, 0, 0)  # no call was made


# ------------------------------------------------------------- the projection
#
# A synthetic corpus with hand-computable arithmetic:
#   corpus 12,000 chars over 4 transcripts; pilot "a" (1,000) and "b" (2,000)
#   calls  x = 4 / 2                          = 2.00
#   chars  x = 12,000 / 3,000                 = 4.00
#   prefix:  writes 300 @1,000 and 500 @2,000 -> k = 0.2, S = 100
#            sum(100 + 0.2L) = 2,800 over pilot 800  = 3.50
#   thinking: mean output 100 @1,000, 200 @2,000 -> e = 1 -> F(1) = 4.00
#   notes:    note chars   50 @1,000, 100 @2,000 -> e = 1 -> F(1) = 4.00

SIZES = {"a": 1000, "b": 2000, "c": 3000, "d": 6000}

BLANK = RunRecord(
    stage=defender.STAGE,
    condition="C1",
    transcript="a",
    sample=0,
    output="",
    model="claude-opus-5",
    effort="medium",
    prompt_hash="a1b2c3d4",
    usage=Usage(0, 0, 0, 0),
    git_sha="0" * 40,
    created_at="2026-08-03T00:00:00Z",
)


def _defender(transcript, sample, output_tokens, note_chars, write=0, read=0):
    return replace(
        BLANK,
        transcript=transcript,
        sample=sample,
        output="n" * note_chars,
        usage=Usage(10, output_tokens, read, write),
    )


PAIR = (
    _defender("a", 0, 100, 50, write=300),
    _defender("a", 1, 100, 50, read=300),
    _defender("b", 0, 200, 100, write=500),
    _defender("b", 1, 200, 100, read=500),
    replace(BLANK, stage=attacker.STAGE, usage=Usage(500, 200, 1000, 0)),
    # The control arm needs a record of its own: without one, `BASES[control]` is
    # never exercised and a mutant that puts it on the wrong basis survives.
    replace(BLANK, stage=control.STAGE, transcript="b", usage=Usage(500, 200, 1000, 0)),
)


def test_the_factors_are_derived_from_the_corpus_and_the_records():
    extrapolation = project(PAIR, SIZES)

    assert extrapolation.piloted == ("a", "b")
    assert (extrapolation.pilot_chars, extrapolation.corpus_chars) == (3000, 12000)
    assert extrapolation.factors[CALLS].value == 2.0
    assert extrapolation.factors[CHARS].value == 4.0
    assert extrapolation.assumed == ()  # every factor measured, none assumed


def test_the_prefix_factor_is_solved_from_the_measured_cache_writes():
    """#10 caches the note-format spec *together with* the transcript, so a prefix
    is `S + k*L` and follows neither the count nor the character ratio. Two pilot
    transcripts of different lengths are two equations in two unknowns."""
    prefix = project(PAIR, SIZES).factors[PREFIX]

    assert prefix.measured
    assert prefix.value == pytest.approx(2800 / 800)  # 3.50
    assert "100 + 0.200/char" in prefix.derivation
    # Strictly between the two bases it would otherwise have had to pick from.
    assert 2.0 < prefix.value < 4.0


def test_one_prefix_is_written_once_and_a_second_write_is_a_ttl_expiry():
    """The write per transcript is the **largest** record's, never the sum.

    #10 writes one prefix per transcript by design, so a second write is a TTL
    expiry or a resumed run re-paying for the same prefix — it says how many
    times the prefix was written, not how big it is. Summing turns a gap in one
    transcript's calls into a claim about prefix *size*, and a gap does not
    arrive evenly across the pair: here the short transcript's second write
    alone makes the solve read `k = -0.20`, degrade to the character ratio, and
    label a measured term `[ASSUMED]`.
    """
    expired = PAIR + (_defender("a", 2, 100, 50, write=300),)
    prefix = project(expired, SIZES).factors[PREFIX]

    assert prefix.measured
    assert "100 + 0.200/char" in prefix.derivation
    assert prefix.value == pytest.approx(2800 / 800)


@pytest.mark.parametrize(
    "short_write, long_write, why",
    [
        (500, 300, "k <= 0: the longer transcript wrote the smaller prefix"),
        (300, 900, "spec < 0: the solve implies a negative fixed cost"),
    ],
)
def test_a_degenerate_prefix_solve_falls_back_rather_than_projecting_nonsense(
    short_write, long_write, why
):
    """Both halves of the guard, and neither was held by anything.

    A prefix that shrinks with transcript length, or one whose constant term is
    negative, is a measurement too noisy to trust rather than a model — and
    extrapolating either produces a projection with no physical reading. The
    fallback is the character ratio, and the point is that it says so.
    """
    records = (
        _defender("a", 0, 100, 50, write=short_write),
        _defender("a", 1, 100, 50, read=short_write),
        _defender("b", 0, 200, 100, write=long_write),
        _defender("b", 1, 200, 100, read=long_write),
    )
    extrapolation = project(records, SIZES)
    prefix = extrapolation.factors[PREFIX]

    assert not prefix.measured, why
    assert prefix.value == extrapolation.factors[CHARS].value
    assert "prefix model unsolved, assuming pure chars" in prefix.derivation
    assert PREFIX in {f.name for f in extrapolation.assumed}


def test_the_defender_input_is_a_per_call_constant_not_a_transcript():
    """`input_tokens` is the post-breakpoint remainder — C2's instruction and
    per-call structure — so it scales by count. Chars would overstate it."""
    projected = project(PAIR, SIZES).stages[defender.STAGE]

    assert projected.bases["input_tokens"] == CALLS
    assert projected.projected.input_tokens == 40 * 2  # four records x 10, x2.00
    assert projected.projected.input_tokens != 40 * 4


def test_the_output_term_is_scaled_by_a_fitted_elasticity():
    """The term that decides the verdict: thinking bills at $25/MTok and is ~97% of
    the defender line. Output doubles as length doubles here, so `e` fits at 1 and
    the factor is the character ratio — *measured*, where a flat count would have
    asserted e=0 and come in at half."""
    projected = project(PAIR, SIZES).stages[defender.STAGE]

    assert projected.bases["output_tokens"] == THINKING
    assert projected.projected.output_tokens == 600 * 4
    assert projected.projected.output_tokens != 600 * 2  # the flat-count assumption


def test_a_flat_output_fits_the_count_ratio_and_a_proportional_one_the_chars_ratio():
    """F(0) is the count ratio and F(1) the character ratio, so the two multipliers
    this gate used to hardcode are the endpoints of the one it now fits."""
    flat = (
        _defender("a", 0, 100, 50, write=300),
        _defender("a", 1, 100, 50, read=300),
        _defender("b", 0, 100, 50, write=500),
        _defender("b", 1, 100, 50, read=500),
    )

    assert project(flat, SIZES).factors[THINKING].value == pytest.approx(2.0)
    assert project(PAIR, SIZES).factors[THINKING].value == pytest.approx(4.0)


def test_the_attacker_and_the_control_arm_both_scale_on_note_length():
    """Neither ever sees a transcript. Their spend follows the note, and note
    length is measured directly off the stored notes."""
    stages = project(PAIR, SIZES).stages

    for name in (attacker.STAGE, control.STAGE):
        assert set(stages[name].bases.values()) == {NOTES}
        assert stages[name].projected.input_tokens == 500 * 4
        assert stages[name].projected.output_tokens == 200 * 4


def test_the_projected_cost_is_the_hand_computed_number():
    """Priced through `runs_report`, so the gate holds no second copy of the cache
    multipliers — one of them drifting is invisible in the total."""
    extrapolation = project(PAIR, SIZES)

    # defender: input 40x2=80; cache read 800x3.5=2,800; write 800x3.5=2,800;
    #           output 600x4=2,400
    #   billed input 80 + 280 + 3,500 = 3,860 -> $0.0193; output -> $0.0600
    assert extrapolation.stages[defender.STAGE].cost == pytest.approx(0.0793)
    # attacker: input 2,000 + read 4,000x0.1 = 2,400 -> $0.0120; output 800 -> $0.0200
    assert extrapolation.stages[attacker.STAGE].cost == pytest.approx(0.032)
    assert extrapolation.stages[control.STAGE].cost == pytest.approx(0.032)
    assert extrapolation.cost == pytest.approx(0.1433)
    assert extrapolation.stages[control.STAGE].cost == pytest.approx(
        price(extrapolation.stages[control.STAGE].projected, "claude-opus-5")
    )


def test_switching_the_pilot_pair_moves_every_factor_with_it():
    """The multipliers are read off the records, so no constant can go stale (#55)."""
    on_the_long_one = project((_defender("d", 0, 100, 50, write=300),), SIZES)

    assert on_the_long_one.factors[CALLS].value == 4.0
    assert on_the_long_one.factors[CHARS].value == 2.0


def test_a_stage_with_no_declared_basis_raises_rather_than_guessing():
    with pytest.raises(ValueError, match="BASES"):
        project(PAIR + (replace(BLANK, stage="grader", usage=Usage(1, 1, 0, 0)),), SIZES)


def test_a_stage_that_mixes_models_refuses_to_project():
    """One dollar figure off two models' rates belongs to neither."""
    mixed = PAIR + (replace(PAIR[0], sample=9, model="claude-sonnet-5"),)

    with pytest.raises(ValueError, match="mixes models"):
        project(mixed, SIZES)


def test_records_naming_a_transcript_outside_the_corpus_raise():
    with pytest.raises(ValueError, match="absent from the corpus"):
        project((replace(PAIR[0], transcript="zzz"),), SIZES)


def test_no_defender_record_means_no_known_pilot_share():
    with pytest.raises(ValueError, match="which transcripts were piloted"):
        project((PAIR[4],), SIZES)


# ------------------------------------------------------- fallbacks and the span


def _equal_length_pilot():
    """Both piloted transcripts the same length: no lever arm for any fit."""
    sizes = {"a": 1000, "e": 1000, "c": 3000, "d": 6000}
    records = (
        _defender("a", 0, 100, 50, write=300),
        _defender("a", 1, 100, 50, read=300),
        _defender("e", 0, 200, 100, write=300),
        _defender("e", 1, 200, 100, read=300),
    )
    return records, sizes


def test_a_pilot_with_no_lever_arm_falls_back_and_says_so():
    """Silence here is the danger: a fallback is `e = 0` asserted rather than
    measured, and it looks exactly like a measurement in the output."""
    records, sizes = _equal_length_pilot()
    extrapolation = project(records, sizes)

    assert {f.name for f in extrapolation.assumed} == {PREFIX, THINKING, NOTES}
    assert extrapolation.factors[THINKING].value == extrapolation.factors[CALLS].value
    assert "assuming output is flat per call" in extrapolation.factors[THINKING].derivation


def test_a_fallback_makes_the_gate_exit_non_zero(capsys):
    records, sizes = _equal_length_pilot()

    assert report(records, sizes) == 1

    assert "ASSUMED, not measured" in capsys.readouterr().out


# Scatter within each transcript, and a mean ratio of 1.4 across a 2x lever arm,
# so `e` lands near 0.49 with a standard error near 0.10 — comfortably inside the
# clamp, where the span is a real interval rather than a clipped one.
NOISY = (
    _defender("a", 0, 90, 50, write=300),
    _defender("a", 1, 100, 50, read=300),
    _defender("a", 2, 110, 50, read=300),
    _defender("b", 0, 130, 70, write=500),
    _defender("b", 1, 140, 70, read=500),
    _defender("b", 2, 150, 70, read=500),
)


def test_the_fitted_interval_collapses_on_the_outcome_this_project_expects():
    """Output proportional to length is the expected result, and there the fit
    clamps at both ends and prints a zero-width interval. That reads as
    'confidently bracketed' and means 'no interval was available' — which is the
    whole reason the verdict is a bound instead."""
    tight = project(PAIR, SIZES)

    assert tight.candidates["fit -1 SE"] == pytest.approx(tight.candidates["fit +1 SE"])
    assert tight.bound >= tight.cost  # the fit is one candidate, never the ceiling


def test_the_bound_is_the_largest_cost_over_the_whole_clamped_family():
    """`_clamp` confines every fitted elasticity to [0, 1], so F(0) and F(1) are
    the endpoints of everything the code can produce. The bound needs no fit and
    no standard error, and is never softer than the fit."""
    extrapolation = project(PAIR, SIZES)

    assert set(extrapolation.candidates) == {
        "fit",
        "fit -1 SE",
        "fit +1 SE",
        "e = 0.00",
        "e = 1.00",
    }
    assert extrapolation.bound == max(extrapolation.candidates.values())
    assert extrapolation.bound >= extrapolation.cost


def test_the_bound_is_evaluated_rather_than_assumed_to_sit_at_one_end():
    """Which endpoint is larger is a property of the corpus, not something this
    module gets to declare. On a corpus where the pilot is the *short* end the
    sign inverts, and the bound has to follow it."""
    # In SIZES the pilot is the *short* end, so the char ratio is the larger one.
    short_pilot = project(PAIR, SIZES)
    # Here the two piloted transcripts are the corpus's longest, and it inverts.
    long_pilot = project(PAIR, {"a": 1000, "b": 2000, "c": 100, "d": 100})

    assert short_pilot.candidates["e = 1.00"] > short_pilot.candidates["e = 0.00"]
    assert long_pilot.candidates["e = 0.00"] > long_pilot.candidates["e = 1.00"]
    for extrapolation in (short_pilot, long_pilot):
        assert extrapolation.bound == max(extrapolation.candidates.values())


def test_a_noisy_fit_still_cannot_soften_the_bound():
    """The fitted band is one candidate among five, never the verdict on its own."""
    noisy = project(NOISY, SIZES)

    assert noisy.candidates["fit -1 SE"] < noisy.cost < noisy.candidates["fit +1 SE"]
    assert noisy.bound >= noisy.candidates["fit +1 SE"]
    assert noisy.bound >= noisy.cost


def test_a_fit_too_noisy_to_distinguish_the_endpoints_is_reported_as_noise():
    """`sxx <= 0` fires only on *exactly* equal lengths; the condition that
    actually matters is a lever arm too short relative to the scatter. Two
    transcripts a hair apart fit `e` wildly and clamp silently."""
    sizes = {"a": 1000, "b": 1053, "c": 3000, "d": 6000}
    barely = (
        _defender("a", 0, 40, 50, write=300),
        _defender("a", 1, 160, 50, read=300),
        _defender("b", 0, 300, 100, write=500),
        _defender("b", 1, 100, 100, read=500),
    )
    extrapolation = project(barely, sizes)

    # `notes` is exact here (every note the same length), so only the noisy fit
    # is flagged — the flag tracks the fit's own scatter, not the lever arm alone.
    assert {f.name for f in extrapolation.uninformative} == {THINKING}
    assert extrapolation.factors[THINKING].measured  # a fit happened; it says nothing
    assert abs(float(extrapolation.factors[THINKING].derivation.split()[1])) > 1.0


def test_the_elasticity_is_clamped_to_a_plausible_range():
    """Below zero means longer transcripts produce less output and above one that
    they produce superlinearly more. Either is a finding, not an input — and the
    clamp keeps the factor between the two bases it would otherwise pick between."""
    shrinking = (
        _defender("a", 0, 400, 50, write=300),
        _defender("a", 1, 400, 50, read=300),
        _defender("b", 0, 100, 100, write=500),
        _defender("b", 1, 100, 100, read=500),
    )
    factors = project(shrinking, SIZES).factors

    assert factors[THINKING].value == pytest.approx(factors[CALLS].value)  # clamped at e=0
    assert "-2.00" in factors[THINKING].derivation  # the raw fit is still reported


def test_the_clamp_is_applied_after_the_shift_and_never_before():
    """`_clamp(e + shift*se)`, not `_clamp(e) + shift*se`.

    The two agree everywhere except where they matter: a fit already outside
    [0, 1]. There the clamped-first form walks the shifted candidates back
    *out* of the family the bound is taken over -- an `e = -0.06` projection
    sitting in `candidates` with nothing in `BOUND_ELASTICITIES` covering it,
    and F decreasing in e on a corpus like this one, so the excursion is
    anti-conservative.

    Here e fits at -2.00 +/- 0.06, so all three of the fitted candidates must
    land on the same clamped e = 0 -- and the scatter is real, so they are not
    equal merely because the standard error is zero.
    """
    outside = (
        _defender("a", 0, 380, 50, write=300),
        _defender("a", 1, 400, 50, read=300),
        _defender("a", 2, 420, 50, read=300),
        _defender("b", 0, 95, 100, write=500),
        _defender("b", 1, 100, 100, read=500),
        _defender("b", 2, 105, 100, read=500),
    )
    extrapolation = project(outside, SIZES)

    assert "elasticity -2.00 +/- 0.06, used 0.00" in extrapolation.factors[THINKING].derivation
    assert (
        extrapolation.candidates["fit -1 SE"]
        == extrapolation.candidates["fit"]
        == extrapolation.candidates["fit +1 SE"]
    )


# --------------------------------------------------------- the fit's arithmetic
#
# The verdict rests on these four functions and, until #61's mutation battery,
# every one of them could be broken in a way the rest of the suite waved through.
# The tests below are deliberately unit-level and hand-computed: a projection
# assertion checks that the arithmetic agrees with itself, which is exactly what
# a wrong constant also does.


def test_the_standard_error_is_propagated_on_the_log_scale():
    """The delta method — the one line of the fit that is easiest to lose.

    `ys` are `ln(mean)`, so each point's weight has to be the variance *of the
    log*, `(sem/mean)**2`, not `sem**2`. Drop the division and the fit still
    runs, still prints a `+/-`, and reports it in tokens rather than in units of
    an exponent: on the real pilot that is 4,339x too wide. It no longer gates
    the verdict (the bound does), but it is printed beside the fit and it is the
    number #17 quotes for `e`.

    Hand-computed rather than restated from the code. Two points a factor of two
    apart, three samples each, both with sd/mean = 0.1:

        mean 100, sd 10  -> sem^2 / mean^2 = (100/3) / 100^2 = 1/300
        mean 200, sd 20  -> sem^2 / mean^2 = (400/3) / 200^2 = 1/300

    With two points `(x - xbar) / sxx` is `1 / (x2 - x1)` at both, so
    `se = sqrt(v1 + v2) / |ln L2 - ln L1| = sqrt(1/150) / ln 2`.
    """
    slope, se = pilot._elasticity({1000: [90, 100, 110], 2000: [180, 200, 220]})

    assert slope == pytest.approx(1.0)
    assert se == pytest.approx(math.sqrt(1 / 150) / math.log(2))
    assert se == pytest.approx(0.1178, abs=5e-5)  # and the magnitude, in the open


def test_the_standard_error_of_a_mean_uses_the_sample_variance():
    """`n - 1`, not `n`. One line, and it feeds every `+/-` the gate prints."""
    assert pilot._mean_sem([90, 100, 110]) == (100, pytest.approx(math.sqrt(100 / 3)))
    assert pilot._mean_sem([90, 100, 110])[1] == pytest.approx(5.7735, abs=5e-5)
    assert pilot._mean_sem([7]) == (7, 0.0)  # one sample has no spread to report


def test_a_zero_measurement_falls_back_instead_of_raising():
    """`ys` are `ln(mean)`, so a mean of zero is `math domain error` — a traceback
    where the intended behaviour is a flat count labelled `[ASSUMED]`. A defender
    record carrying zero output tokens is a live possibility, and the gate exists
    to report a number rather than to die holding one."""
    silent = (
        _defender("a", 0, 0, 50, write=300),
        _defender("a", 1, 0, 50, read=300),
        _defender("b", 0, 200, 100, write=500),
        _defender("b", 1, 200, 100, read=500),
    )
    factors = project(silent, SIZES).factors

    assert not factors[THINKING].measured
    assert factors[THINKING].value == factors[CALLS].value
    assert factors[NOTES].measured  # and only the fit that saw the zero degrades


# A refusal's stored body, byte for byte what `defender.run` writes: no note,
# and `runs.failed` keys on the shape rather than on the message.
REFUSAL_BODY = json.dumps({"failed": "the model returned no note"}, indent=2, sort_keys=True)

# Wide notes, so a refusal's ~44-character JSON stub sits against something the
# size of a real handoff note. Both fits are exactly e = 1 before it arrives.
WIDE = (
    _defender("a", 0, 100, 600, write=300),
    _defender("a", 1, 100, 600, read=300),
    _defender("b", 0, 200, 1200, write=500),
    _defender("b", 1, 200, 1200, read=500),
)


def test_a_refused_note_is_excluded_from_both_fits():
    """It carries no note, and its output tokens are what a refusal cost rather
    than a measurement of what a transcript that length makes the model write.

    Non-vacuous by construction: the *same* record — same tokens, same body
    length, differing only in being the `{"failed": ...}` shape — is not
    excluded, and drags both fits well off e = 1.
    """
    refusal = replace(_defender("b", 2, 50, 0), output=REFUSAL_BODY)
    counterfeit = replace(refusal, output="n" * len(REFUSAL_BODY))

    excluded = project(WIDE + (refusal,), SIZES).factors
    included = project(WIDE + (counterfeit,), SIZES).factors

    assert "elasticity +1.00" in excluded[THINKING].derivation
    assert "elasticity +1.00" in excluded[NOTES].derivation
    assert (excluded[THINKING].value, excluded[NOTES].value) == pytest.approx((4.0, 4.0))
    # The refusal is the cheapest generation in the run and the shortest body in
    # it, and it lands on the *long* transcript: both fits flatten.
    assert "elasticity +0.58" in included[THINKING].derivation
    assert included[THINKING].value < 4.0
    assert included[NOTES].value < 4.0


def test_a_pilot_with_no_lever_arm_returns_none_rather_than_dividing_by_zero():
    """`sxx <= 0` is the guard between the fit and a `ZeroDivisionError`.

    It fires only on *exactly* equal log-lengths, which through `project` means
    two lengths so large their logarithms collapse to one float — `points` is
    keyed by length, so anything coarser has already merged into a single point.
    The hazard that actually bites is a lever arm too short relative to the
    scatter, and `UNINFORMATIVE_SE` is what catches that.
    """
    collapsed = {2**60: [100.0, 100.0], 2**60 + 1: [200.0, 200.0]}
    assert math.log(2**60) == math.log(2**60 + 1)  # not vacuous: one x, twice

    assert pilot._elasticity(collapsed) is None


# ------------------------------------------------------------------ the cache


def _cache(stage_name, **groups) -> tuple[RunRecord, ...]:
    return tuple(
        replace(BLANK, stage=stage_name, condition=condition, transcript=t, usage=Usage(**u))
        for condition, per in groups.items()
        for t, u in per.items()
    )


HOT = dict(
    input_tokens=100, output_tokens=1, cache_read_input_tokens=900, cache_creation_input_tokens=0
)
COLD = dict(
    input_tokens=1000, output_tokens=1, cache_read_input_tokens=0, cache_creation_input_tokens=0
)
BARELY = dict(
    input_tokens=1000, output_tokens=1, cache_read_input_tokens=13, cache_creation_input_tokens=0
)


def test_cache_is_reported_per_condition_and_per_transcript():
    rows = cache_rows(_cache(attacker.STAGE, C1={"a": HOT, "b": HOT}, C3={"a": COLD, "b": COLD}))

    assert {(r.axis, r.group) for r in rows} == {
        ("condition", "C1"),
        ("condition", "C3"),
        ("transcript", "a"),
        ("transcript", "b"),
    }


def test_a_condition_that_never_caches_is_caught_behind_a_healthy_pool():
    """C3's scrubbed notes are the shortest artefacts in the pipeline and the ones
    that can fall under Opus 5's 512-token minimum. Pooled with C1 and C2 the ratio
    still reads healthy."""
    records = _cache(
        attacker.STAGE, C1={"a": HOT, "b": HOT}, C2={"a": HOT, "b": HOT}, C3={"a": COLD, "b": COLD}
    )
    pooled = sum(r.usage.cache_read_input_tokens for r in records) / sum(
        r.usage.input_tokens + r.usage.cache_read_input_tokens for r in records
    )

    assert pooled > 0.55  # looks fine
    assert [w for w in cache_warnings(cache_rows(records)) if "condition=C3" in w]


def test_one_transcript_never_caching_is_invisible_per_condition():
    """The defender's prefix is per *transcript*, so condition rows cannot see it:
    A caching perfectly and B never caching at all gives three identical,
    healthy-looking condition rows and #14's actual check goes unanswered."""
    records = _cache(
        defender.STAGE,
        C1={"a": HOT, "b": COLD},
        C2={"a": HOT, "b": COLD},
        C3={"a": HOT, "b": COLD},
    )
    rows = cache_rows(records)
    by_condition = [r for r in rows if r.axis == "condition"]

    assert {round(r.ratio, 2) for r in by_condition} == {0.45}  # identical, and above the floor
    assert cache_warnings(by_condition) == []

    warnings = cache_warnings(rows)
    assert [w for w in warnings if "transcript=b" in w]
    assert not [w for w in warnings if "transcript=a" in w]


def test_a_cache_working_at_one_percent_is_a_finding_not_a_pass():
    """The old threshold was `read == 0`, so a prefix hitting 1.3% of the time — as
    broken as one hitting never — passed in silence."""
    rows = cache_rows(_cache(attacker.STAGE, C1={"a": BARELY, "b": BARELY}))

    assert rows[0].ratio == pytest.approx(0.0128, abs=1e-3)
    assert cache_warnings(rows)


def test_a_single_record_group_is_exempt_because_the_first_call_must_write():
    assert cache_warnings([Cache(attacker.STAGE, "transcript", "a", 1, 1000, 0, 400)]) == []


def test_a_healthy_group_warns_about_nothing():
    assert cache_warnings([Cache(attacker.STAGE, "condition", "C1", 5, 100, 900, 0)]) == []


def test_the_pilot_itself_caches_everywhere_it_should(store):
    """End to end: the fields the warnings read are the fields the pilot writes."""
    pilot_run(store)

    assert cache_warnings(cache_rows(store.read_all())) == []


# ----------------------------------------------------------------- the report


def test_the_report_shows_every_multiplier_and_where_it_came_from(capsys):
    """#55's real failure was invisibility: the number was wrong and nothing in the
    output said which multiplier had produced it."""
    report(PAIR, SIZES)

    out = capsys.readouterr().out
    assert "12,000 corpus chars / 3,000 pilot chars" in out
    assert "4 corpus transcripts / 2 piloted" in out
    assert "solved from measured cache writes" in out
    assert "elasticity +1.00" in out
    for term in TERMS:
        assert term in out


def test_the_records_column_is_projected_and_not_the_pilot_count(capsys):
    """Display-only, and wrong in the operator's headline table: dropping the
    count factor prints the pilot's 30 records beside a 270-call cost, which
    reads as a projection that forgot to project."""
    report(PAIR, SIZES)

    lines = capsys.readouterr().out.splitlines()
    header = next(i for i, l in enumerate(lines) if l.startswith("stage") and "cache_write" in l)
    # 4 defender records x the 2.00 count factor; 1 each for attacker and control.
    assert [l.split()[:2] for l in lines[header + 1 : header + 4]] == [
        [attacker.STAGE, "2"],
        [control.STAGE, "2"],
        [defender.STAGE, "8"],
    ]


def test_the_report_clears_a_run_that_fits_the_budget(capsys):
    assert report(PAIR, SIZES) == 0

    assert "fits, with" in capsys.readouterr().out


def test_the_report_refuses_a_run_that_does_not_fit(capsys):
    assert report(PAIR, SIZES, budget=0.01) == 1

    out = capsys.readouterr().out
    assert "OVER by 0.13" in out
    assert "claude-sonnet-5" in out  # the lever ladder, least damaging first


def test_the_verdict_is_read_at_the_bound_and_not_at_the_fit(capsys):
    """The one that matters. A budget between the fit and the bound must fail:
    the fitted standard error is a repeatability interval and far too narrow to
    be a safety margin, so it may not be what a run is launched on."""
    extrapolation = project(NOISY, SIZES)
    between = (extrapolation.candidates["fit +1 SE"] + extrapolation.bound) / 2
    assert extrapolation.cost < between < extrapolation.bound

    assert report(NOISY, SIZES, budget=between) == 1

    out = capsys.readouterr().out
    assert "OVER by" in out
    assert "read at the bound" in out


def test_the_report_shows_every_candidate_the_bound_is_taken_over(capsys):
    report(PAIR, SIZES)

    out = capsys.readouterr().out
    assert "conservative bound" in out
    for label in ("fit", "fit -1 SE", "fit +1 SE", "e = 0.00", "e = 1.00"):
        assert label in out
    assert "<-- bound" in out


def test_a_fit_that_says_nothing_makes_the_gate_report_non_zero(capsys):
    sizes = {"a": 1000, "b": 1053, "c": 3000, "d": 6000}
    barely = (
        _defender("a", 0, 40, 50, write=300),
        _defender("a", 1, 160, 50, read=300),
        _defender("b", 0, 300, 100, write=500),
        _defender("b", 1, 100, 100, read=500),
    )

    assert report(barely, sizes) == 1

    assert "fit is noise, not a measurement" in capsys.readouterr().out


def test_a_failed_note_makes_the_gate_report_non_zero(capsys):
    failure = pilot.Failure(control.STAGE, "C1", "a", 0, "stripping left 12%")

    assert report(PAIR, SIZES, [failure]) == 1

    assert "stripping left 12%" in capsys.readouterr().out


def test_a_stage_that_mixes_effort_makes_the_gate_report_non_zero(capsys):
    """The escalation ladder's first rung is re-running at a lower effort, and
    `runs.exists()` keys on four coordinates — so it keeps every record from the
    old setting, #13 aggregates across both, and the re-measured cost lands low.
    The reassuring direction, which is why the gate has to say so."""
    mixed = PAIR + (replace(PAIR[0], sample=9, effort="low"),)

    assert report(mixed, SIZES) == 1

    assert "defender mixes effort: low, medium" in capsys.readouterr().out


def test_the_report_states_what_the_pilot_pair_spans(capsys):
    report(PAIR, SIZES)

    out = capsys.readouterr().out
    assert "pilot pair spans 1,000-2,000 chars" in out
    assert "corpus mean of 3,000" in out


def test_the_report_asks_for_the_half_no_projection_covers(capsys):
    """#14 also wants a human read of three C1 notes. If they are garbage,
    everything downstream measures nothing and no number here would say so."""
    report(PAIR, SIZES)

    assert "read three C1 notes" in capsys.readouterr().out


def test_the_report_prints_on_a_console_that_is_not_utf8(capsys):
    """CI runs on Windows and the operator reads this in a terminal. An em dash in
    printed prose raises UnicodeEncodeError under cp1252 — the gate would die
    holding the number it was built to report."""
    records, sizes = _equal_length_pilot()
    report(
        records + (replace(BLANK, stage=attacker.STAGE, transcript="a", usage=Usage(**COLD)),),
        sizes,
        [pilot.Failure(control.STAGE, "C1", "a", 0, "stripping left 12%")],
        budget=0.01,
    )

    capsys.readouterr().out.encode("cp1252")


# -------------------------------------------------------------------- the cli


@pytest.fixture
def real_corpus(monkeypatch, fixture_root, canaries):
    """Point `main`'s corpus load at the fixture this session built.

    `main` reads the real 18 transcripts, and `load_all` binds `fixture/` as a
    default argument, so the module attribute is what has to move. Never the real
    `fixture/`: a test must not depend on a developer having run the generator
    (conftest.py), and CI has not.
    """
    from src.transcript import TRANSCRIPTS as CORPUS
    from src.transcript import load_all

    monkeypatch.setattr(
        "src.transcript.load_all",
        lambda *a, **k: load_all(CORPUS, fixture_root=fixture_root, canaries=canaries),
    )


def test_main_spends_nothing_without_run(tmp_path, capsys, real_corpus):
    """Money is opt-in. `--run` is the only path that calls a model."""
    assert pilot.main([], tmp_path) == 1

    out = capsys.readouterr().out
    assert "has not run" in out
    assert "--run" in out


def test_main_rejects_an_unknown_flag(tmp_path, capsys):
    assert pilot.main(["--yolo"], tmp_path) == 2

    assert "usage:" in capsys.readouterr().err


def test_main_reports_off_a_populated_store(tmp_path, capsys, monkeypatch):
    store = RunStore(tmp_path)
    for record in PAIR:
        store.write(record)
    monkeypatch.setattr(
        "src.transcript.load_all",
        lambda *a, **k: tuple(SimpleNamespace(id=i, rendered="x" * n) for i, n in SIZES.items()),
    )

    assert pilot.main([], tmp_path) == 0

    out = capsys.readouterr().out
    assert "projected full run" in out
    assert "12,000 corpus chars / 3,000 pilot chars" in out


def test_the_pilot_pair_spans_the_corpus(real_corpus):
    """Every fit needs a lever arm, and the prefix solve needs two distinct
    lengths. A pair at one end of the range degrades all three to assumptions."""
    from src.transcript import load_all

    sizes = {t.id: len(t.rendered) for t in load_all()}
    piloted = sorted(sizes[t] for t in pilot.PILOT)

    assert set(pilot.PILOT) <= set(sizes)
    assert piloted[0] == min(sizes.values())
    assert piloted[-1] == max(sizes.values())


def test_the_budget_matches_the_one_claude_md_documents():
    """The constant and the prose have to agree, and only one of them is tested."""
    text = (Path(__file__).resolve().parents[1] / "CLAUDE.md").read_text(encoding="utf-8")

    assert f"~${BUDGET:.0f}" in text
