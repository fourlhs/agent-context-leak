"""Spend per stage, measured from `runs/` — `python -m src.runs_report`.

Budget is checked against the logs, never against a guess (CLAUDE.md, Budget),
which is what the pilot gate (#14) reads.

**These are list prices**, in USD per million tokens, and this report is an
estimate. The authoritative figure is the bill.

Cache reads bill at ~0.1x the input rate and cache writes at ~1.25x it, so both
are modelled explicitly. With #10's cached prefixes those two terms dominate the
defender bill: pricing a cache read as full input would over-report the cached
prefix by 10x, and the resulting number would fail the gate for no reason.

The token columns are printed alongside the cost because #14 also has to check
that `cache_read_input_tokens` is non-zero — a zero there means the cached
prefix is being missed and the defender bill is roughly twice what it should be.
"""

from dataclasses import dataclass
from pathlib import Path

from src.runs import RUNS, RunRecord, RunStore

# model -> (input $/MTok, output $/MTok). The one place prices live.
# `claude-sonnet-5` is on introductory pricing (2.00 / 10.00) through
# 2026-08-31; list prices are used so an estimate never lands under the bill.
PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
}

CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25


@dataclass(frozen=True)
class StageTotals:
    calls: int
    input_tokens: int
    cache_read_input_tokens: int
    cache_creation_input_tokens: int
    output_tokens: int
    cost: float


def cost(record: RunRecord) -> float:
    """Dollars for one call. Raises on an unpriced model rather than counting
    it as free — a silent zero is a budget check that passes for the wrong
    reason."""
    if record.model not in PRICES:
        raise ValueError(f"{record.model!r} is not in PRICES; add it before reporting")
    rate_in, rate_out = PRICES[record.model]
    u = record.usage
    billed_input = (
        u.input_tokens
        + u.cache_read_input_tokens * CACHE_READ_MULTIPLIER
        + u.cache_creation_input_tokens * CACHE_WRITE_MULTIPLIER
    )
    return (billed_input * rate_in + u.output_tokens * rate_out) / 1_000_000


def _totals(records: tuple[RunRecord, ...]) -> StageTotals:
    return StageTotals(
        calls=len(records),
        input_tokens=sum(r.usage.input_tokens for r in records),
        cache_read_input_tokens=sum(r.usage.cache_read_input_tokens for r in records),
        cache_creation_input_tokens=sum(
            r.usage.cache_creation_input_tokens for r in records
        ),
        output_tokens=sum(r.usage.output_tokens for r in records),
        cost=sum(cost(r) for r in records),
    )


def summarise(records: tuple[RunRecord, ...]) -> dict[str, StageTotals]:
    """Totals per stage. Only real stages — the `TOTAL` row is main's, so a
    caller iterating this never has to filter out a row that is not a stage."""
    stages: dict[str, list[RunRecord]] = {}
    for r in records:
        stages.setdefault(r.stage, []).append(r)
    return {stage: _totals(tuple(rs)) for stage, rs in sorted(stages.items())}


def _row(label: str, t: StageTotals) -> str:
    return (
        f"{label:<10}{t.calls:>7}{t.input_tokens:>12}{t.cache_read_input_tokens:>12}"
        f"{t.cache_creation_input_tokens:>13}{t.output_tokens:>12}{t.cost:>11.4f}"
    )


def main(root: Path = RUNS) -> None:
    records = RunStore(root).read_all()
    if not records:
        print(f"no run records under {root}")
        return

    print(
        f"{'stage':<10}{'calls':>7}{'input':>12}{'cache_read':>12}"
        f"{'cache_write':>13}{'output':>12}{'cost $':>11}"
    )
    for stage, totals in summarise(records).items():
        print(_row(stage, totals))

    total = _totals(records)
    print(_row("TOTAL", total))

    if total.cache_read_input_tokens == 0:
        print(
            f"\nwarning: cache_read_input_tokens is 0 across {total.calls} calls — "
            "the cached prefix is never hit, so the defender bill is roughly\n"
            "double what it should be (CLAUDE.md, Prompt caching)."
        )


if __name__ == "__main__":
    main()
