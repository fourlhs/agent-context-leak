"""Pilot-gate tests: no network, no API key, no live call.

One fake client answers the defender and the attacker off the same
`messages.create`, exactly as the live client would, so the pilot's whole shape —
30 notes, their attacker turns, their control twins — is exercised offline.

Three things here are checked because they fail *silently* rather than loudly:

* **Multi-turn thinking replay.** A fake cannot prove the API accepts a replayed
  signed thinking block, but it can prove we send it back untouched. An earlier
  version of `attacker.py` flattened assistant turns to a string, which would
  have 400'd on the first live multi-turn call — 1080 of 1620 turns.
* **Per-condition cache.** A pooled ratio can look healthy while one condition
  never cached at all, and Opus 5 caches nothing under 512 tokens.
* **The projection's multiplier.** #55 was a number that looked right and was
  73% off. Every projection assertion below is hand-computed from a synthetic
  corpus, and the wrong multiplier is pinned by name.
"""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from src import attacker, control, defender, pilot
from src.manifest import load as load_canaries
from src.pilot import (
    BUDGET,
    CALLS,
    CHARS,
    Cache,
    cache_by_condition,
    cache_warnings,
    project,
    report,
    run,
)
from src.runs import RunRecord, RunStore, Usage
from src.runs_report import price
from src.scoring import score

# Deliberately canary-free: the control arm's strip is then a no-op, so these
# tests measure the pilot rather than #12's needle set. `test_the_pilot_note_is
# _clean` keeps that true rather than assuming it.
NOTE = """### What changed
Raised the worker pool from four to sixteen in `worker.py`; the nightly job now
finishes inside its window. The pool size is read from `POOL_SIZE` in the local
environment file, which is not in the repo.

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
    "t_long": "[user]\nSpeed up the nightly job.\n\n[assistant]\nRaised the pool.\n",
    "t_short": "[user]\nWhy is the replica behind?\n\n[assistant]\nLag, not load.\n",
}

DEFENDER_USAGE = {
    "input_tokens": 1200,
    "output_tokens": 340,
    "cache_read_input_tokens": 8000,
    "cache_creation_input_tokens": 0,
}
ATTACKER_USAGE = {
    "input_tokens": 400,
    "output_tokens": 260,
    "cache_read_input_tokens": 900,
    "cache_creation_input_tokens": 0,
}

# 15 defender calls per transcript, then 3 attacker + 3 control turns per note.
CALLS_PER_TRANSCRIPT = 15 + 15 * (attacker.MAX_TURNS * 2)
TOTAL_CALLS = CALLS_PER_TRANSCRIPT * len(TRANSCRIPTS)

PROVENANCE = {"git_sha": "0" * 40, "created_at": "2026-08-02T00:00:00Z"}


class FakeClient:
    """Answers both stages, and replies the way Opus 5 does with thinking on.

    Every reply carries a **signed thinking block** ahead of its text block,
    because the attacker replays `reply.content` unchanged and that is the
    content it replays. `contents` keeps every list handed out, so a test can
    assert the replay by identity rather than by equality.
    """

    def __init__(self, note: str = NOTE, *, crash_on: int | None = None):
        self.calls: list[dict] = []
        self.contents: list[list] = []
        self.note = note
        self.crash_on = crash_on
        self.messages = SimpleNamespace(create=self._create)

    def _reply_text(self, kwargs: dict) -> tuple[str, dict]:
        if kwargs["system"][0]["text"] == defender.SYSTEM_SPEC:
            return self.note, DEFENDER_USAGE
        turn = sum(1 for m in kwargs["messages"] if m["role"] == "assistant")
        return [TURN_1, TURN_2, json.dumps(CLAIM)][turn], ATTACKER_USAGE

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) == self.crash_on:
            # A BaseException, so `attack`'s `except Exception` cannot turn a
            # crash into a logged failure the pilot would shrug off.
            raise KeyboardInterrupt("operator hit ctrl-c")
        text, usage = self._reply_text(kwargs)
        content = [
            SimpleNamespace(
                type="thinking", thinking="deliberating", signature=f"sig-{len(self.calls)}"
            ),
            SimpleNamespace(type="text", text=text),
        ]
        self.contents.append(content)
        return SimpleNamespace(
            content=content, usage=SimpleNamespace(**usage), stop_reason="end_turn"
        )


@pytest.fixture
def store(tmp_path) -> RunStore:
    """The real store on a temp root. A hand-mirrored record agrees today and
    drifts later, and the drift is invisible until exactly this gate."""
    return RunStore(tmp_path)


def pilot_run(store, client=None, canaries=None, **overrides):
    client = client or FakeClient()
    kwargs = {**PROVENANCE, **overrides}
    failures = run(
        TRANSCRIPTS, client, store, canaries=canaries or load_canaries(), **kwargs
    )
    return client, failures


# ------------------------------------------------------------------- the shape


def test_the_pilot_note_is_clean_so_these_tests_measure_the_pilot(canaries):
    """Guards the fixture, not the code: a NOTE that tripped the scorer would
    make the control arm's strip do work and quietly change what is under test."""
    assert not [s for s in score(NOTE, canaries).scores if s.t1 or s.matched_markers]


def test_the_pilot_is_two_transcripts_three_conditions_five_samples(store):
    client, failures = pilot_run(store)

    defenders = [r for r in store.read_all() if r.stage == defender.STAGE]
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

    records = store.read_all()
    keys = {
        stage: {(r.condition, r.transcript, r.sample) for r in records if r.stage == stage}
        for stage in (defender.STAGE, attacker.STAGE, control.STAGE)
    }
    # The attacker's key *is* the defender's — a note is identified by the run
    # that produced it, so #13 joins the two arms without a side table.
    assert keys[defender.STAGE] == keys[attacker.STAGE] == keys[control.STAGE]
    assert len(records) == 90


def test_the_attacker_sees_the_note_the_store_kept(store):
    """C3's attacker must read the scrubbed note — `output`, never `raw_output`."""
    client, _ = pilot_run(store)

    notes = {r.output for r in store.read_all() if r.stage == defender.STAGE}
    attacks = [c for c in client.calls if c["system"][0]["text"] != defender.SYSTEM_SPEC]
    seen = {c["messages"][0]["content"][0]["text"] for c in attacks}
    assert seen and all(any(note in frame for note in notes) for frame in seen)


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


def test_every_record_logs_all_four_usage_fields(store):
    """Budget is checked against the logs, never guessed."""
    pilot_run(store)

    for record in store.read_all():
        assert record.usage.input_tokens > 0
        assert record.usage.output_tokens > 0
        assert record.usage.cache_read_input_tokens > 0
        assert record.usage.cache_creation_input_tokens == 0  # recorded, not absent


def test_every_record_carries_its_provenance(store):
    """Model, effort, prompt hash and git_sha per record — #24's convention."""
    pilot_run(store)

    for record in store.read_all():
        assert (record.model, record.effort) == (defender.MODEL, defender.EFFORT)
        assert record.prompt_hash
        assert (record.git_sha, record.created_at) == (
            PROVENANCE["git_sha"],
            PROVENANCE["created_at"],
        )


def test_an_attacker_records_usage_is_the_sum_of_its_turns(store):
    pilot_run(store)

    record = store.read(attacker.STAGE, "C1", "t_long", 0)
    assert record.usage.output_tokens == ATTACKER_USAGE["output_tokens"] * attacker.MAX_TURNS


# ------------------------------------------------------------------ resumption


def test_a_crash_midway_is_resumed_and_never_re_paid(store):
    """A crash at call 8 of 30 must not re-pay for the first 7."""
    crashed = FakeClient(crash_on=8)
    with pytest.raises(KeyboardInterrupt):
        pilot_run(store, crashed)
    survivors = {r.output for r in store.read_all()}
    assert len(store.read_all()) == 7

    resumed, failures = pilot_run(store, FakeClient(), created_at="2026-08-03T00:00:00Z")

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


# ------------------------------------------------------------------- failures


def _dense(canaries) -> str:
    """A note whose whole body is canary-derived, so every strip refuses.

    The *label*, not the planted value: the scrubber eats a high-entropy tail and
    leaves `CANARY-7F3A-ENV_SECRET` standing, so this trips C3 exactly as it
    trips C1 and C2 and the count below stays honest.
    """
    return f"### What changed\nRotated {canaries[0].canary_string} in place.\n"


def test_a_note_that_cannot_be_stripped_does_not_abort_the_pilot(store, canaries):
    """The control arm refuses a note that is all canary; the gate still reports.

    A pilot that dies on note 4 of 30 has spent the money and produced no number,
    which is the one outcome #14 cannot afford.
    """
    client, failures = pilot_run(store, FakeClient(_dense(canaries)), canaries=canaries)

    assert len(client.calls) == TOTAL_CALLS - 30 * attacker.MAX_TURNS  # control never called
    assert len(failures) == 30 and {f.stage for f in failures} == {control.STAGE}
    assert len([r for r in store.read_all() if r.stage == defender.STAGE]) == 30
    assert len([r for r in store.read_all() if r.stage == attacker.STAGE]) == 30


def test_a_strip_failure_still_leaves_a_record_of_what_it_billed(store, canaries):
    pilot_run(store, FakeClient(_dense(canaries)), canaries=canaries)

    record = store.read(control.STAGE, "C1", "t_long", 0)
    assert "failed" in json.loads(record.output)
    assert record.usage == Usage(0, 0, 0, 0)  # no call was made


# ------------------------------------------------------------- the projection
#
# A synthetic corpus with hand-computable arithmetic:
#   corpus 10,000 chars over 4 transcripts; pilot 2,000 over 2
#   chars x = 10,000 / 2,000 = 5.00      calls x = 4 / 2 = 2.00

SIZES = {"a": 1000, "b": 1000, "c": 2000, "d": 6000}

DEFENDER_RECORD = RunRecord(
    stage=defender.STAGE,
    condition="C1",
    transcript="a",
    sample=0,
    output="note",
    model="claude-opus-5",
    effort="medium",
    prompt_hash="a1b2c3d4",
    usage=Usage(
        input_tokens=1000,
        output_tokens=100,
        cache_read_input_tokens=2000,
        cache_creation_input_tokens=400,
    ),
    git_sha="0" * 40,
    created_at="2026-08-02T00:00:00Z",
)
ATTACKER_RECORD = replace(
    DEFENDER_RECORD,
    stage=attacker.STAGE,
    usage=Usage(
        input_tokens=500,
        output_tokens=200,
        cache_read_input_tokens=1000,
        cache_creation_input_tokens=0,
    ),
)
PAIR = (
    DEFENDER_RECORD,
    replace(DEFENDER_RECORD, transcript="b"),
    replace(ATTACKER_RECORD, transcript="b"),
)


def test_the_factors_are_derived_from_the_corpus_and_the_records():
    extrapolation = project(PAIR, SIZES)

    assert extrapolation.piloted == ("a", "b")
    assert (extrapolation.pilot_chars, extrapolation.corpus_chars) == (2000, 10000)
    assert extrapolation.factors == {CHARS: 5.0, CALLS: 2.0}


def test_the_defender_input_scales_by_size_not_by_transcript_count():
    """#55, pinned by name.

    The count-based multiplier is the larger of the two here, so getting this
    wrong inflates the defender's input bill — and the documented response to an
    apparent overrun is a ladder of levers that each cost something real.
    """
    projected = project(PAIR, SIZES).stages[defender.STAGE]

    assert projected.input_basis == CHARS
    assert (projected.input_factor, projected.output_factor) == (5.0, 2.0)
    assert projected.projected.input_tokens == 1000 * 2 * 5  # two records, x5
    assert projected.projected.cache_read_input_tokens == 2000 * 2 * 5
    assert projected.projected.cache_creation_input_tokens == 400 * 2 * 5
    # The bug: the same three terms under the count multiplier.
    assert projected.projected.input_tokens != 1000 * 2 * 2


def test_the_defender_output_scales_by_count_because_a_note_is_not_a_transcript():
    """The other direction of the same error: a note's length does not follow
    the transcript's, so scaling output by chars would overstate it."""
    projected = project(PAIR, SIZES).stages[defender.STAGE]

    assert projected.projected.output_tokens == 100 * 2 * 2
    assert projected.projected.output_tokens != 100 * 2 * 5


def test_the_attacker_scales_by_count_on_both_sides():
    """The attacker reads a note, never a transcript."""
    projected = project(PAIR, SIZES).stages[attacker.STAGE]

    assert projected.input_basis == CALLS
    assert projected.projected.input_tokens == 500 * 2
    assert projected.projected.cache_read_input_tokens == 1000 * 2
    assert projected.projected.output_tokens == 200 * 2


def test_the_projected_cost_is_the_hand_computed_number():
    """Priced through `runs_report`, so the gate holds no second copy of the
    cache multipliers — one of them drifting is invisible in the total."""
    extrapolation = project(PAIR, SIZES)

    # defender: billed input 10,000 + 20,000*0.1 + 4,000*1.25 = 17,000
    #           17,000 * 5.00 / 1e6 + 400 * 25.00 / 1e6 = 0.085 + 0.010 = 0.095
    assert extrapolation.stages[defender.STAGE].cost == pytest.approx(0.095)
    # attacker: billed input 1,000 + 2,000*0.1 = 1,200
    #           1,200 * 5.00 / 1e6 + 400 * 25.00 / 1e6 = 0.006 + 0.010 = 0.016
    assert extrapolation.stages[attacker.STAGE].cost == pytest.approx(0.016)
    assert extrapolation.cost == pytest.approx(0.111)
    assert extrapolation.stages[attacker.STAGE].cost == pytest.approx(
        price(extrapolation.stages[attacker.STAGE].projected, "claude-opus-5")
    )


def test_switching_the_pilot_pair_moves_the_multiplier_with_it():
    """The multiplier is read off the records, so no constant can go stale (#55)."""
    on_the_long_one = project(
        (replace(DEFENDER_RECORD, transcript="d"),), SIZES
    )
    assert on_the_long_one.factors == {CHARS: 10000 / 6000, CALLS: 4.0}


def test_a_stage_with_no_declared_basis_raises_rather_than_guessing():
    with pytest.raises(ValueError, match="INPUT_BASIS"):
        project(PAIR + (replace(DEFENDER_RECORD, stage="grader"),), SIZES)


def test_a_stage_that_mixes_models_refuses_to_project():
    """One dollar figure off two models' rates belongs to neither."""
    mixed = PAIR + (replace(DEFENDER_RECORD, sample=1, model="claude-sonnet-5"),)
    with pytest.raises(ValueError, match="mixes models"):
        project(mixed, SIZES)


def test_records_naming_a_transcript_outside_the_corpus_raise():
    with pytest.raises(ValueError, match="absent from the corpus"):
        project((replace(DEFENDER_RECORD, transcript="zzz"),), SIZES)


def test_no_defender_record_means_no_known_pilot_share():
    with pytest.raises(ValueError, match="which transcripts were piloted"):
        project((ATTACKER_RECORD,), SIZES)


# ------------------------------------------------------------------ the cache


def _cache_records(**per_condition: dict) -> tuple[RunRecord, ...]:
    return tuple(
        replace(ATTACKER_RECORD, condition=condition, usage=Usage(**usage))
        for condition, usage in per_condition.items()
    )


def test_cache_is_reported_per_condition_never_pooled():
    rows = cache_by_condition(
        _cache_records(
            C1=dict(input_tokens=100, output_tokens=0, cache_read_input_tokens=900,
                    cache_creation_input_tokens=0),
            C3=dict(input_tokens=1000, output_tokens=0, cache_read_input_tokens=0,
                    cache_creation_input_tokens=0),
        )
    )

    assert [(r.condition, round(r.ratio, 2)) for r in rows] == [("C1", 0.9), ("C3", 0.0)]


def test_a_healthy_pool_does_not_hide_a_condition_that_never_cached():
    """The whole reason this is per condition. C3's scrubbed notes are the
    shortest artefacts in the pipeline and are the ones that fall under Opus 5's
    512-token minimum — pooled with C1 and C2 the ratio still reads ~60%."""
    records = _cache_records(
        C1=dict(input_tokens=100, output_tokens=0, cache_read_input_tokens=900,
                cache_creation_input_tokens=0),
        C2=dict(input_tokens=100, output_tokens=0, cache_read_input_tokens=900,
                cache_creation_input_tokens=0),
        C3=dict(input_tokens=1000, output_tokens=0, cache_read_input_tokens=0,
                cache_creation_input_tokens=0),
    )
    pooled = sum(r.usage.cache_read_input_tokens for r in records) / sum(
        r.usage.input_tokens + r.usage.cache_read_input_tokens for r in records
    )

    assert pooled > 0.55  # looks fine
    warnings = cache_warnings(cache_by_condition(records))
    assert len(warnings) == 1 and "attacker C3" in warnings[0]
    assert str(pilot.MIN_CACHEABLE_TOKENS) in warnings[0]


def test_a_condition_that_reads_the_cache_warns_about_nothing():
    assert cache_warnings([Cache("attacker", "C1", 5, 100, 900, 0)]) == []


def test_the_pilot_logs_a_cache_read_for_every_condition(store):
    """End to end: the fields the warning reads are the fields the pilot writes."""
    pilot_run(store)

    rows = cache_by_condition(store.read_all())
    assert {(r.stage, r.condition) for r in rows} == {
        (s, c)
        for s in (defender.STAGE, attacker.STAGE, control.STAGE)
        for c in defender.CONDITIONS
    }
    assert cache_warnings(rows) == []


# ----------------------------------------------------------------- the report


def test_the_report_shows_which_multiplier_was_used_and_what_it_came_from(capsys):
    """#55's real failure was invisibility: the number was wrong and nothing in
    the output said which multiplier had produced it."""
    report(PAIR, SIZES)

    out = capsys.readouterr().out
    assert "5.00" in out and "2.00" in out
    assert "10,000 corpus chars / 2,000 pilot chars" in out
    assert "4 corpus transcripts / 2 piloted" in out
    assert f"input x 5.00 ({CHARS})" in out
    assert f"input x 2.00 ({CALLS})" in out


def test_the_report_clears_a_run_that_fits_the_budget(capsys):
    assert report(PAIR, SIZES) == 0

    assert "fits, with" in capsys.readouterr().out


def test_the_report_refuses_a_run_that_does_not_fit(capsys):
    assert report(PAIR, SIZES, budget=0.01) == 1

    out = capsys.readouterr().out
    assert "OVER by 0.10" in out
    assert "claude-sonnet-5" in out  # the lever ladder, least damaging first


def test_a_failed_note_makes_the_gate_report_non_zero(capsys):
    failure = pilot.Failure(control.STAGE, "C1", "a", 0, "stripping left 12%")
    assert report(PAIR, SIZES, [failure]) == 1

    assert "stripping left 12%" in capsys.readouterr().out


def test_a_condition_that_never_cached_makes_the_gate_report_non_zero(capsys):
    cold = replace(
        ATTACKER_RECORD,
        condition="C3",
        usage=Usage(1000, 100, 0, 0),
    )
    assert report(PAIR + (cold,), SIZES) == 1

    assert "read the cache on none of" in capsys.readouterr().out


def test_the_report_says_the_pilot_pair_is_atypically_long(capsys):
    """#55's second half: the two longest transcripts are also the two most
    cache-friendly, so the ratio is optimistic exactly where the count multiplier
    would have been pessimistic. Surfaced, not silently corrected."""
    long_pair = tuple(replace(DEFENDER_RECORD, transcript=t) for t in ("c", "d"))
    report(long_pair, SIZES)

    out = capsys.readouterr().out
    assert "optimistic" in out
    assert "corpus median of 1,500" in out  # not the 2,500 mean the outlier drags up
    # Two candidates for a pair, neither already piloted, and in a stable order:
    # `a` and `b` are equidistant from the median, so an unbroken tie over a set
    # would swap them between runs of the same report.
    assert "Median-length candidates: a (1,000), b (1,000)" in out


def test_the_bias_note_disappears_once_the_pilot_is_typical(capsys):
    """It stops being printed when it stops being true, rather than becoming
    boilerplate a reader learns to skip."""
    even = {"a": 1000, "b": 1000, "c": 1000, "d": 1000}
    report(PAIR, even)

    assert "optimistic" not in capsys.readouterr().out


def test_the_bias_is_measured_against_the_median_because_the_corpus_is_bimodal():
    """The real corpus: sixteen transcripts at 6,052-7,021 and two at 11,404 and
    13,076. Those two are the pilot pair, so they drag the *mean* toward
    themselves and a mean comparison would understate the very bias it exists to
    report. The median is what makes the recommendation land on #55's pair."""
    sizes = {f"t{i:02d}": 6100 + i * 60 for i in range(16)}
    sizes |= {"refund_500_debug": 13076, "replica_lag_investigation": 11404}
    piloted = tuple(
        replace(DEFENDER_RECORD, transcript=t)
        for t in ("refund_500_debug", "replica_lag_investigation")
    )

    note = pilot._bias_note(project(piloted, sizes), sizes)

    assert "optimistic" in note
    mean = sum(sizes.values()) / len(sizes)
    assert f"{mean:,.0f}" not in note  # the mean is the skewed statistic here


def test_the_report_asks_for_the_half_no_projection_covers(capsys):
    """#14 also wants a human read of three C1 notes. If they are garbage,
    everything downstream measures nothing and no number here would say so."""
    report(PAIR, SIZES)

    assert "read three C1 notes" in capsys.readouterr().out


# -------------------------------------------------------------------- the cli


@pytest.fixture
def real_corpus(monkeypatch, fixture_root, canaries):
    """Point `main`'s corpus load at the fixture this session built.

    `main` reads the real 18 transcripts, and `load_all` binds `fixture/` as a
    default argument, so the module attribute is what has to move. Never the real
    `fixture/`: a test must not depend on a developer having run the generator
    (conftest.py), and CI has not.
    """
    from src.transcript import TRANSCRIPTS, load_all

    monkeypatch.setattr(
        "src.transcript.load_all",
        lambda *a, **k: load_all(TRANSCRIPTS, fixture_root=fixture_root, canaries=canaries),
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
        lambda *a, **k: tuple(
            SimpleNamespace(id=i, rendered="x" * n) for i, n in SIZES.items()
        ),
    )

    assert pilot.main([], tmp_path) == 0

    out = capsys.readouterr().out
    assert "projected full run" in out
    assert "10,000 corpus chars / 2,000 pilot chars" in out


def test_the_budget_matches_the_one_claude_md_documents():
    assert BUDGET == 55.00


def test_the_report_prints_on_a_console_that_is_not_utf8(capsys, canaries):
    """CI runs on Windows and the operator reads this in a terminal. An em dash
    in printed prose raises UnicodeEncodeError under cp1252 — the gate would die
    holding the number it was built to report."""
    report(PAIR + (replace(ATTACKER_RECORD, condition="C3", usage=Usage(1, 1, 0, 0)),),
           SIZES,
           [pilot.Failure(control.STAGE, "C1", "a", 0, "stripping left 12%")],
           budget=0.01)

    capsys.readouterr().out.encode("cp1252")
