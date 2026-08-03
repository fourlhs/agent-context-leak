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

Two things this report says out loud because nothing else would. A stage
holding more than one model, effort, or prompt hash means a relaunch reused
records written under the old settings — `exists()` cannot see that, and the
re-measured cost comes out *low*. And an unreadable record turns the total into
a floor, so it is labelled one and the exit code is non-zero.
"""

from dataclasses import dataclass
from pathlib import Path

from src.runs import RUNS, RunRecord, RunStore, Usage

# model -> (input $/MTok, output $/MTok). The one place prices live.
PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
}

# Introductory rates, valid through INTRO_EXPIRY. Reported *alongside* the list
# price, never instead of it: the list price keeps an estimate from landing
# under the bill, but CLAUDE.md's last escalation lever is switching the
# attacker to claude-sonnet-5 specifically to get this rate — quoting only the
# list price would have the gate reject a lever that actually fits.
INTRO_PRICES: dict[str, tuple[float, float]] = {"claude-sonnet-5": (2.00, 10.00)}
INTRO_EXPIRY = "2026-08-31"

CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25

# Fields that must not vary within a stage — see the module docstring.
PROVENANCE = ("model", "effort")

# `prompt_hash` is checked within (stage, condition) rather than within a stage,
# because it is *supposed* to vary by condition: C2 appends its instruction, and
# C1 and C3 share a hash by construction. Checked per stage it fires on every
# real defender run, and a warning that is always on is a warning nobody reads —
# which matters more since #14 folds these into the gate's own exit code.
CONDITIONAL_PROVENANCE = ("prompt_hash",)


@dataclass(frozen=True)
class StageTotals:
    calls: int
    input_tokens: int
    cache_read_input_tokens: int
    cache_creation_input_tokens: int
    output_tokens: int
    cost: float


def price(
    usage: Usage, model: str, prices: dict[str, tuple[float, float]] = PRICES
) -> float:
    """Dollars for `usage` on `model`. Raises on an unpriced model rather than
    counting it as free — a silent zero is a budget check that passes for the
    wrong reason.

    Takes counts rather than a record so that a *projected* usage prices through
    exactly these rates: #14 scales the pilot's measured tokens and must not
    carry a second copy of the cache multipliers to do it.
    """
    if model not in prices:
        raise ValueError(f"{model!r} is not in PRICES; add it before reporting")
    rate_in, rate_out = prices[model]
    billed_input = (
        usage.input_tokens
        + usage.cache_read_input_tokens * CACHE_READ_MULTIPLIER
        + usage.cache_creation_input_tokens * CACHE_WRITE_MULTIPLIER
    )
    return (billed_input * rate_in + usage.output_tokens * rate_out) / 1_000_000


def cost(record: RunRecord, prices: dict[str, tuple[float, float]] = PRICES) -> float:
    """Dollars for one call."""
    return price(record.usage, record.model, prices)


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


def _by_stage(records: tuple[RunRecord, ...]) -> dict[str, tuple[RunRecord, ...]]:
    stages: dict[str, list[RunRecord]] = {}
    for r in records:
        stages.setdefault(r.stage, []).append(r)
    return {stage: tuple(rs) for stage, rs in sorted(stages.items())}


def summarise(records: tuple[RunRecord, ...]) -> dict[str, StageTotals]:
    """Totals per stage. Only real stages — the `TOTAL` row is main's, so a
    caller iterating this never has to filter out a row that is not a stage."""
    return {stage: _totals(rs) for stage, rs in _by_stage(records).items()}


def _mixed(label: str, records: tuple[RunRecord, ...], fields: tuple[str, ...]) -> list[str]:
    warnings = []
    for field in fields:
        values = sorted({getattr(r, field) for r in records})
        if len(values) > 1:
            warnings.append(f"{label} mixes {field}: {', '.join(values)}")
    return warnings


def provenance_warnings(records: tuple[RunRecord, ...]) -> list[str]:
    """One line per group that holds more than one value of a provenance field.

    `exists()` keys on (stage, condition, transcript, sample), so relaunching
    after changing the prompt, the model, or the effort keeps every completed
    record and calls nothing. The concrete case: the pilot runs at effort
    `medium`, comes in hot, someone applies escalation lever 1 and relaunches at
    `low`. Nothing errors, `runs/` quietly holds both, #13 aggregates across
    them, and the re-measured cost lands low — the reassuring direction.

    Model and effort are checked across a whole stage, because neither may vary at
    all. `prompt_hash` is checked within a condition, because it varies *by*
    condition on purpose — see `CONDITIONAL_PROVENANCE`.
    """
    warnings = []
    by_condition: dict[tuple[str, str], list[RunRecord]] = {}
    for stage, rs in _by_stage(records).items():
        warnings += _mixed(stage, rs, PROVENANCE)
        for r in rs:
            by_condition.setdefault((r.stage, r.condition), []).append(r)
    for (stage, condition), rs in sorted(by_condition.items()):
        warnings += _mixed(f"{stage}/{condition or '-'}", tuple(rs), CONDITIONAL_PROVENANCE)
    return warnings


def _row(label: str, t: StageTotals) -> str:
    return (
        f"{label:<10}{t.calls:>7}{t.input_tokens:>12}{t.cache_read_input_tokens:>12}"
        f"{t.cache_creation_input_tokens:>13}{t.output_tokens:>12}{t.cost:>11.4f}"
    )


def main(root: Path = RUNS) -> int:
    """Print the report; return the process exit code."""
    records, unreadable = RunStore(root).read_readable()
    if not records and not unreadable:
        print(f"no run records under {root}")
        return 0

    print(
        f"{'stage':<10}{'calls':>7}{'input':>12}{'cache_read':>12}"
        f"{'cache_write':>13}{'output':>12}{'cost $':>11}"
    )
    for stage, totals in summarise(records).items():
        print(_row(stage, totals))

    total = _totals(records)
    print(_row("TOTAL", total))

    intro = sum(cost(r, {**PRICES, **INTRO_PRICES}) for r in records)
    if intro != total.cost:
        print(
            f"\nTOTAL at introductory pricing, through {INTRO_EXPIRY}: {intro:.4f} "
            f"({', '.join(sorted(INTRO_PRICES))})"
        )

    warnings = provenance_warnings(records)
    if total.calls and total.cache_read_input_tokens == 0:
        warnings.append(
            f"no call in {total.calls} read the cache: the prefix is never hit, "
            "so the defender bill is roughly double what it should be"
        )
    for warning in warnings:
        print(f"\nwarning: {warning}")

    if unreadable:
        # Deliberately not fatal: a floor an operator can act on beats a
        # traceback. Deliberately not silent either — under-reporting spend is
        # the failure the gate exists to catch, so it is labelled and the exit
        # code says the number is not the whole picture.
        for path in unreadable:
            print(f"\nerror: unreadable record, not counted above: {path}")
        print(
            f"TOTAL above is INCOMPLETE: a floor over {total.calls} readable "
            f"records, with {len(unreadable)} unreadable."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
