from dataclasses import replace

import pytest

from src.runs import RunRecord, RunStore, Usage
from src.runs_report import (
    CACHE_READ_MULTIPLIER,
    CACHE_WRITE_MULTIPLIER,
    PRICES,
    cost,
    main,
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
    # 0.1x, not 1x — treating a cache read as full-price input would inflate
    # the defender bill by ~10x on the cached prefix.
    assert cost(as_cache_read) == pytest.approx(5.00 * CACHE_READ_MULTIPLIER)
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


    assert cost(as_cache_write) == pytest.approx(5.00 * CACHE_WRITE_MULTIPLIER)


def test_unpriced_model_raises_rather_than_costing_nothing():
    with pytest.raises(ValueError, match="not in PRICES"):
        cost(replace(DEFENDER, model="claude-haiku-4-5"))


def test_main_prints_the_stage_rows_and_the_total(store, capsys):
    main(store.root)

    out = capsys.readouterr().out
    assert f"{TOTAL_COST:.4f}" in out
    assert f"{DEFENDER_COST:.4f}" in out
    assert f"{ATTACKER_COST:.4f}" in out
    assert "TOTAL" in out
    assert "cache_read" in out
    assert "warning" not in out  # this fixture does read the cache


def test_main_warns_when_no_call_ever_reads_the_cache(tmp_path, capsys):
    RunStore(tmp_path).write(ATTACKER)

    main(tmp_path)

    assert "cache_read_input_tokens is 0" in capsys.readouterr().out


def test_main_on_an_empty_runs_dir_says_so(tmp_path, capsys):
    main(tmp_path)

    assert "no run records" in capsys.readouterr().out
