from dataclasses import replace

import pytest

from src.runs import RunRecord, RunStore, Usage
from src.runs_report import (
    CACHE_READ_MULTIPLIER,
    CACHE_WRITE_MULTIPLIER,
    INTRO_EXPIRY,
    INTRO_PRICES,
    PRICES,
    cost,
    main,
    provenance_warnings,
    summarise,
)

# Round token counts so the expected dollars below are hand-computable.
#
#   defender, claude-opus-5 @ $5.00 / $25.00 per MTok
#     billed input = 1_000_000 + 2_000_000*0.1 + 400_000*1.25 = 1_700_000
#     1.7 * 5.00 + 0.1 * 25.00 = 8.50 + 2.50 = $11.00
#   attacker, claude-sonnet-5 @ $3.00 / $15.00 per MTok, no cache
#     0.5 * 3.00 + 0.2 * 15.00 = 1.50 + 3.00 = $4.50
#   total                                                        = $15.50
DEFENDER_COST = 11.00
ATTACKER_COST = 4.50
TOTAL_COST = 15.50

DEFENDER = RunRecord(
    stage="defender",
    condition="C1",
    transcript="t01",
    sample=0,
    output="note",
    model="claude-opus-5",
    effort="medium",
    prompt_hash="a1b2c3d4",
    usage=Usage(
        input_tokens=1_000_000,
        output_tokens=100_000,
        cache_read_input_tokens=2_000_000,
        cache_creation_input_tokens=400_000,
    ),
    git_sha="0123456789abcdef0123456789abcdef01234567",
    created_at="2026-07-31T21:04:00+00:00",
)

ATTACKER = replace(
    DEFENDER,
    stage="attacker",
    condition="",
    model="claude-sonnet-5",
    usage=Usage(
        input_tokens=500_000,
        output_tokens=200_000,
        cache_read_input_tokens=0,
        cache_creation_input_tokens=0,
    ),
)


@pytest.fixture
def store(tmp_path):
    store = RunStore(tmp_path)
    store.write(DEFENDER)
    store.write(ATTACKER)
    return store


def test_prices_cover_both_models_in_play():
    assert PRICES["claude-opus-5"] == (5.00, 25.00)
    assert PRICES["claude-sonnet-5"] == (3.00, 15.00)


def test_cost_of_a_single_record_is_the_hand_computed_number():
    assert cost(DEFENDER) == pytest.approx(DEFENDER_COST)
    assert cost(ATTACKER) == pytest.approx(ATTACKER_COST)


def test_totals_are_per_stage_and_add_up(store):
    summary = summarise(store.read_all())

    assert list(summary) == ["attacker", "defender"]
    assert summary["defender"].cost == pytest.approx(DEFENDER_COST)
    assert summary["attacker"].cost == pytest.approx(ATTACKER_COST)
    assert sum(t.cost for t in summary.values()) == pytest.approx(TOTAL_COST)
    assert summary["defender"].cache_read_input_tokens == 2_000_000
    assert summary["defender"].calls == 1


def test_cache_reads_are_priced_at_the_reduced_rate():
    blank = Usage(
        input_tokens=0,
        output_tokens=0,
        cache_read_input_tokens=0,
        cache_creation_input_tokens=0,
    )
    as_input = replace(DEFENDER, usage=replace(blank, input_tokens=1_000_000))
    as_cache_read = replace(
        DEFENDER, usage=replace(blank, cache_read_input_tokens=1_000_000)
    )

    assert cost(as_input) == pytest.approx(5.00)
    # 0.50, hand-computed: 1 MTok at $5.00 x 0.1. Writing it as
    # `5.00 * CACHE_READ_MULTIPLIER` puts the constant on both sides of the
    # assertion, so a wrong multiplier proves itself.
    assert cost(as_cache_read) == pytest.approx(0.50)
    assert CACHE_READ_MULTIPLIER == 0.1
    assert cost(as_cache_read) < cost(as_input)


def test_cache_writes_are_priced_at_the_premium_rate():
    as_cache_write = replace(
        DEFENDER,
        usage=Usage(
            input_tokens=0,
            output_tokens=0,
            cache_read_input_tokens=0,
            cache_creation_input_tokens=1_000_000,
        ),
    )


    # 6.25, hand-computed: 1 MTok at $5.00 x 1.25, and not spelled with the
    # constant this assertion exists to check.
    assert cost(as_cache_write) == pytest.approx(6.25)
    assert CACHE_WRITE_MULTIPLIER == 1.25


def test_unpriced_model_raises_rather_than_costing_nothing():
    with pytest.raises(ValueError, match="not in PRICES"):
        cost(replace(DEFENDER, model="claude-haiku-4-5"))


def test_main_prints_the_stage_rows_and_the_total(store, capsys):
    assert main(store.root) == 0

    out = capsys.readouterr().out
    assert f"{TOTAL_COST:.4f}" in out
    assert f"{DEFENDER_COST:.4f}" in out
    assert f"{ATTACKER_COST:.4f}" in out
    assert "TOTAL" in out
    assert "cache_read" in out
    assert "warning" not in out  # this fixture reads the cache, one setting each


def test_main_warns_when_no_call_ever_reads_the_cache(tmp_path, capsys):
    RunStore(tmp_path).write(ATTACKER)

    assert main(tmp_path) == 0

    assert "no call in 1 read the cache" in capsys.readouterr().out


def test_main_on_an_empty_runs_dir_says_so(tmp_path, capsys):
    assert main(tmp_path) == 0

    assert "no run records" in capsys.readouterr().out


def test_provenance_warning_fires_per_field_and_per_stage():
    # The escalation-lever case: half the attacker stage was rerun at `low`
    # while `exists()` kept every `medium` record from the pilot.
    records = (DEFENDER, ATTACKER, replace(ATTACKER, sample=1, effort="low"))

    assert provenance_warnings(records) == ["attacker mixes effort: low, medium"]


def test_provenance_warning_covers_model_and_prompt_hash():
    mixed = (
        DEFENDER,
        replace(DEFENDER, sample=1, model="claude-sonnet-5", prompt_hash="deadbeef"),
    )

    assert provenance_warnings(mixed) == [
        "defender mixes model: claude-opus-5, claude-sonnet-5",
        # Per condition, not per stage: both records are C1, so this is a real
        # drift rather than C2 being C2.
        "defender/C1 mixes prompt_hash: a1b2c3d4, deadbeef",
    ]


def test_c2_having_its_own_prompt_hash_is_not_a_warning():
    """It is supposed to: C2 appends its instruction and C1/C3 share a hash by
    construction. Checked per stage this fires on every real defender run, and
    #14 folds these warnings into the gate's own exit code — so a permanent
    false positive would make the gate permanently red."""
    by_condition = (
        DEFENDER,
        replace(DEFENDER, condition="C2", prompt_hash="deadbeef"),
        replace(DEFENDER, condition="C3"),
    )

    assert provenance_warnings(by_condition) == []


def test_one_setting_per_stage_warns_about_nothing(store):
    assert provenance_warnings(store.read_all()) == []


def test_main_prints_the_provenance_warning(tmp_path, capsys):
    s = RunStore(tmp_path)
    s.write(DEFENDER)
    s.write(replace(DEFENDER, sample=1, effort="low"))

    assert main(tmp_path) == 0

    assert "warning: defender mixes effort: low, medium" in capsys.readouterr().out


def test_intro_pricing_is_reported_alongside_the_list_price(store, capsys):
    # Escalation lever 4 is switching the attacker to claude-sonnet-5 for this
    # rate: 0.5 * 2.00 + 0.2 * 10.00 = $3.00, so the total drops to $25.00.
    assert INTRO_PRICES["claude-sonnet-5"] == (2.00, 10.00)

    main(store.root)

    out = capsys.readouterr().out
    assert f"{TOTAL_COST:.4f}" in out  # list price still the headline
    assert f"{DEFENDER_COST + 3.00:.4f}" in out
    assert INTRO_EXPIRY in out


def test_an_all_opus_run_prints_no_intro_line(tmp_path, capsys):
    RunStore(tmp_path).write(DEFENDER)

    main(tmp_path)

    assert "introductory" not in capsys.readouterr().out


def test_one_unreadable_record_still_yields_a_labelled_floor(store, capsys):
    bad = store.write(replace(DEFENDER, sample=1))
    bad.write_text("{ truncated", encoding="utf-8")

    # Not a traceback: the operator gets a number, told it is a floor.
    assert main(store.root) == 1

    out = capsys.readouterr().out
    assert f"{TOTAL_COST:.4f}" in out
    assert "INCOMPLETE" in out
    assert str(bad) in out
