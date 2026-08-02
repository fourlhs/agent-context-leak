"""#14's gate: spend a measured amount, project the full run, then stop.

Two transcripts x three conditions x five samples, plus the attacker turns over
every note it writes and the control arm beside them. The *measured* usage then
comes back out of `runs/`, is scaled to the full corpus, and is compared against
budget. It is a hard stop, not a task: nothing launches the full run until this
reports a number.

**The multiplier is derived, never named.** #14 originally read "multiply by 9" —
one transcript count over another — and #55 found that wrong for the pair it was
written against. The corpus is bimodal, both pilots sit in the long mode, and
`24,480 x 9 = 220,320` chars against a corpus of `127,287` overstates the
defender's input bill by 73%. The damage is not the spend; it is that the gate
reports an overrun that is not there, and the documented response to an overrun
is a ladder of levers that each cost something real — n from 5 to 3, the control
arm down to a stratified subset, the attacker down to `claude-sonnet-5`, which
costs the symmetry argument and turns T3 back into a lower bound. So the
projection scales by measured *size*, reads the pilot's own share off the run
records rather than off a constant here, and prints both multipliers with their
derivation beside the number they produced.

**Two multipliers, because two things scale differently.** The defender re-reads
a whole transcript on every call, so its uncached input, its cache reads and its
cache writes all follow the corpus's *characters*. Its output is one note, and
every other stage reads one note, so those follow the corpus's *count*. Applying
the count to the defender's input is #55; applying characters to the attacker
would understate it by the same arithmetic pointed the other way. `INPUT_BASIS`
is the whole rule, and a stage missing from it raises rather than defaulting to
either — a stage silently projected on the wrong basis is exactly the class of
defect this gate exists to catch.

**What this gate cannot tell you.** Stated here, and printed with the number,
because an unqualified projection is how the last three defects in this project
shipped — as plausible wrong numbers rather than crashes.

- It corrects for the pilot pair's *size*, not for its *content*. Thinking volume
  is the largest single term in the attacker's bill and it keys on how much a
  note gives an attacker to chase, which no character count predicts.
- The cache-read ratio is the pilot pair's own. On the current pair those are the
  two longest transcripts in the corpus and therefore the most cache-friendly, so
  the ratio is optimistic at the same time as a count-based multiplier would have
  been pessimistic — two errors in opposite directions that cannot be separated
  afterwards from the run records. Arithmetic cannot correct it; piloting nearer
  the corpus median can, and that is a choice about which transcripts to run.
  `_bias_note` says so in the report whenever the pilot's mean length is off the
  corpus's, so it stops being said once it stops being true.
- Attacker turn count varies — a note that fails on turn 2 billed two turns — so
  the projection carries whatever failure rate 30 notes happened to show.
- These are list prices. `runs_report` says so; the authoritative figure is the
  bill.
- It says nothing about whether the notes are any good. #14 also asks for a human
  read of three of them, and if C1's notes are garbage everything downstream
  measures nothing. That part is not automatable and the report asks for it.

**Money is opt-in.** `python -m src.pilot` reports off `runs/` and calls nothing;
only `--run` spends. Resume is the store's: every stage skips what `runs/` already
holds, so a crash at call 23 of 30 re-pays for none of the first 22.
"""

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src import attacker, control, defender, runs_report
from src.attacker import AttackFailure
from src.control import StripError
from src.runs import RUNS, RunRecord, RunStore, Usage
from src.runs_report import StageTotals, price, summarise

# The pair #14 pilots. Not a projection input — `project` reads which transcripts
# actually ran off the records, so changing this moves the multiplier with it.
PILOT = ("refund_500_debug", "replica_lag_investigation")

# CLAUDE.md, Budget: ~$18 defender + ~$36 attacker and control.
BUDGET = 55.00

# What each term of the bill is proportional to — see the module docstring.
CHARS, CALLS = "chars", "calls"
INPUT_BASIS = {defender.STAGE: CHARS, attacker.STAGE: CALLS, control.STAGE: CALLS}

# Opus 5 caches nothing shorter than this, so a condition can read zero while the
# pooled ratio looks healthy (CLAUDE.md, prompt caching).
MIN_CACHEABLE_TOKENS = 512

# Below this the pilot's mean transcript length is close enough to the corpus's
# that the cache-friendliness bias is not worth a paragraph.
BIAS_TOLERANCE = 0.10


@dataclass(frozen=True)
class Failure:
    """A note the pilot could not attack or strip. Collected, not raised."""

    stage: str
    condition: str
    transcript: str
    sample: int
    message: str

    def __str__(self) -> str:
        return f"{self.stage} {self.condition}/{self.transcript}/{self.sample}: {self.message}"


@dataclass(frozen=True)
class Projection:
    """One stage's measured spend, and the same stage scaled to the full corpus.

    `input_basis` travels with the factors because it is the thing #55 got wrong:
    a projection whose output does not say which multiplier it used, and what
    that multiplier was derived from, is unauditable after the fact.
    """

    stage: str
    model: str
    measured: StageTotals
    input_basis: str
    input_factor: float
    output_factor: float
    projected: Usage
    cost: float


@dataclass(frozen=True)
class Extrapolation:
    """Every stage's projection, plus the derivation both multipliers came from."""

    piloted: tuple[str, ...]
    corpus: tuple[str, ...]
    pilot_chars: int
    corpus_chars: int
    stages: dict[str, Projection]

    @property
    def factors(self) -> dict[str, float]:
        return {
            CHARS: self.corpus_chars / self.pilot_chars,
            CALLS: len(self.corpus) / len(self.piloted),
        }

    @property
    def cost(self) -> float:
        return sum(p.cost for p in self.stages.values())


@dataclass(frozen=True)
class Cache:
    """One (stage, condition)'s input side, split by how it was billed."""

    stage: str
    condition: str
    records: int
    uncached: int  # `usage.input_tokens` — the part that paid full price
    read: int
    written: int

    @property
    def total(self) -> int:
        return self.uncached + self.read + self.written

    @property
    def ratio(self) -> float:
        """Fraction of the input side served from cache; 0.0 with no input."""
        return self.read / self.total if self.total else 0.0


# ------------------------------------------------------------------ the calls


def run(
    rendered: Mapping[str, str],
    client,
    store: RunStore,
    *,
    canaries,
    git_sha: str,
    created_at: str,
    conditions: Sequence[str] = defender.CONDITIONS,
    samples: int = defender.SAMPLES,
) -> list[Failure]:
    """The pilot's calls, in order, skipping whatever `store` already holds.

    A whole transcript's notes are written before anything attacks them, so an
    interrupted pilot leaves `runs/` holding complete notes rather than notes
    nobody ever attacked — and the resume gate has something to skip.

    A note that cannot be attacked or stripped is **collected, not raised**: both
    modules already wrote a record carrying what that note billed (#11, #12), and
    a gate that aborts on note 4 of 30 has spent the money and reported nothing.
    A *truncated* note is the exception and propagates, because it says
    `MAX_TOKENS` is wrong for this corpus and 29 more calls under a known-broken
    ceiling is not a measurement.
    """
    failures: list[Failure] = []
    for transcript, text in rendered.items():
        defender.run(
            text,
            transcript,
            client,
            store,
            git_sha=git_sha,
            created_at=created_at,
            conditions=conditions,
            samples=samples,
        )
        for condition in conditions:
            for sample in range(samples):
                record = store.read(defender.STAGE, condition, transcript, sample)
                if record is None:
                    # `defender.run` has just guaranteed this key. Skipping it
                    # would retire a note nobody attacked and leave T3 short a
                    # pair with nothing in `runs/` to show it.
                    raise RuntimeError(
                        f"no defender record at {condition}/{transcript}/{sample} "
                        "after writing it: the store disagrees with itself"
                    )
                # `output`, never `raw_output`: C3's attacker sees the scrubbed
                # note, and the control arm strips the note that was attacked.
                note = record.output
                try:
                    attacker.run(
                        note,
                        transcript,
                        condition,
                        client,
                        store,
                        git_sha=git_sha,
                        created_at=created_at,
                        sample=sample,
                    )
                except AttackFailure as exc:
                    failures.append(
                        Failure(attacker.STAGE, condition, transcript, sample, str(exc))
                    )
                try:
                    control.run(
                        note,
                        transcript,
                        condition,
                        client,
                        store,
                        canaries=canaries,
                        git_sha=git_sha,
                        created_at=created_at,
                        sample=sample,
                    )
                except (AttackFailure, StripError) as exc:
                    failures.append(
                        Failure(control.STAGE, condition, transcript, sample, str(exc))
                    )
    return failures


# ------------------------------------------------------------- the projection


def _scale(totals: StageTotals, input_factor: float, output_factor: float) -> Usage:
    """Input-side terms by one factor, output by the other.

    Rounded, because a projected token count is still a count — and because a
    fractional token in a `Usage` would be a lie about the field it sits in.
    """
    return Usage(
        input_tokens=round(totals.input_tokens * input_factor),
        output_tokens=round(totals.output_tokens * output_factor),
        cache_read_input_tokens=round(totals.cache_read_input_tokens * input_factor),
        cache_creation_input_tokens=round(
            totals.cache_creation_input_tokens * input_factor
        ),
    )


def project(records: Sequence[RunRecord], sizes: Mapping[str, int]) -> Extrapolation:
    """Scale the pilot's measured spend to the whole corpus.

    `sizes` is the corpus, transcript id -> rendered chars. The pilot's own share
    is derived from the records — which transcripts the defender actually ran —
    rather than read off `PILOT`, so switching the pilot pair moves the
    multiplier with it and cannot leave a stale constant behind (#55).
    """
    piloted = sorted({r.transcript for r in records if r.stage == defender.STAGE})
    if not piloted:
        raise ValueError(
            "no defender records: nothing says which transcripts were piloted, "
            "and a multiplier over an unknown pilot share is a guess"
        )
    unknown = sorted({r.transcript for r in records} - set(sizes))
    if unknown:
        raise ValueError(f"records name transcripts absent from the corpus: {unknown}")

    pilot_chars = sum(sizes[t] for t in piloted)
    factors = {
        CHARS: sum(sizes.values()) / pilot_chars,
        CALLS: len(sizes) / len(piloted),
    }

    stages = {}
    for stage, totals in summarise(records).items():
        models = sorted({r.model for r in records if r.stage == stage})
        if len(models) != 1:
            # Not a warning. Scaling one number off two models' rates produces a
            # dollar figure that belongs to neither.
            raise ValueError(f"{stage} mixes models {models}: cannot project one cost")
        basis = INPUT_BASIS.get(stage)
        if basis is None:
            raise ValueError(
                f"{stage!r} has no entry in INPUT_BASIS; add one rather than "
                "letting it default to a basis nobody chose"
            )
        projected = _scale(totals, factors[basis], factors[CALLS])
        stages[stage] = Projection(
            stage=stage,
            model=models[0],
            measured=totals,
            input_basis=basis,
            input_factor=factors[basis],
            output_factor=factors[CALLS],
            projected=projected,
            cost=price(projected, models[0]),
        )
    return Extrapolation(
        piloted=tuple(piloted),
        corpus=tuple(sorted(sizes)),
        pilot_chars=pilot_chars,
        corpus_chars=sum(sizes.values()),
        stages=stages,
    )


# ------------------------------------------------------------------ the cache


def cache_by_condition(records: Sequence[RunRecord]) -> tuple[Cache, ...]:
    """The input side per (stage, condition), never pooled — see `cache_warnings`."""
    rows: dict[tuple[str, str], list[RunRecord]] = {}
    for r in records:
        rows.setdefault((r.stage, r.condition), []).append(r)
    return tuple(
        Cache(
            stage=stage,
            condition=condition,
            records=len(rs),
            uncached=sum(r.usage.input_tokens for r in rs),
            read=sum(r.usage.cache_read_input_tokens for r in rs),
            written=sum(r.usage.cache_creation_input_tokens for r in rs),
        )
        for (stage, condition), rs in sorted(rows.items())
    )


def cache_warnings(rows: Sequence[Cache]) -> list[str]:
    """One line per (stage, condition) that never read the cache.

    Pooled, a cache ratio can read healthy while one condition never cached at
    all. Opus 5's minimum cacheable prefix is 512 tokens and C3's scrubbed notes
    are the shortest artefacts in the pipeline, so the attacker's and the control
    arm's C3 prefixes are the ones most likely to fall under it — and a condition
    that never caches costs roughly double on every one of its turns.
    """
    return [
        f"{row.stage} {row.condition} read the cache on none of its {row.records} "
        f"record(s): that condition's prefix never hits, and under "
        f"{MIN_CACHEABLE_TOKENS} tokens it never will"
        for row in rows
        if row.records and not row.read
    ]


# ----------------------------------------------------------------- the report


def _bias_note(extrapolation: Extrapolation, sizes: Mapping[str, int]) -> str:
    """Say it when the pilot pair is not the corpus's typical length.

    Against the **median**, not the mean: the corpus is bimodal and the mean is
    dragged upward by the two outliers that are currently being piloted, so a
    mean comparison understates exactly the bias it is meant to surface.

    The projection corrects for size; the *cache ratio* it reports cannot be
    corrected by arithmetic at all, because a longer transcript amortises its
    cached prefix over the same 15 calls. Printed only while it is true, so it
    disappears if the pilot moves to the median rather than becoming boilerplate
    nobody reads.
    """
    pilot_mean = extrapolation.pilot_chars / len(extrapolation.piloted)
    lengths = sorted(sizes.values())
    half = len(lengths) // 2
    median = (
        lengths[half] if len(lengths) % 2 else (lengths[half - 1] + lengths[half]) / 2
    )
    if abs(pilot_mean - median) <= BIAS_TOLERANCE * median:
        return ""
    longer = pilot_mean > median
    # A transcript already being piloted is not a candidate to switch to. Ties
    # break on the name, because the input is a set and two transcripts of equal
    # distance would otherwise swap places between runs of the same report.
    candidates = sorted(
        set(sizes) - set(extrapolation.piloted), key=lambda t: (abs(sizes[t] - median), t)
    )
    return (
        f"\nnote: the pilot pair averages {pilot_mean:,.0f} chars against a corpus median of "
        f"{median:,.0f}.\n"
        f"      {'Longer' if longer else 'Shorter'} transcripts amortise a cached prefix over the "
        f"same {len(defender.CONDITIONS) * defender.SAMPLES} calls, so the\n"
        f"      cache-read ratio above is {'optimistic' if longer else 'pessimistic'} for the full "
        f"run. The size multiplier\n"
        f"      corrects the token totals; it cannot correct this. Piloting nearer the corpus\n"
        f"      median would. That is a choice about which transcripts to run, and it is\n"
        f"      surfaced here rather than taken.\n"
        f"      Median-length candidates: "
        + ", ".join(f"{t} ({sizes[t]:,})" for t in candidates[: len(extrapolation.piloted)])
        + "\n"
    )


def _usage_row(label: str, records: int, u: Usage, cost: float) -> str:
    return (
        f"{label:<10}{records:>9}{u.input_tokens:>12}{u.cache_read_input_tokens:>12}"
        f"{u.cache_creation_input_tokens:>13}{u.output_tokens:>12}{cost:>11.2f}"
    )


def _projection_table(extrapolation: Extrapolation) -> list[str]:
    lines = [
        f"{'stage':<10}{'records':>9}{'input':>12}{'cache_read':>12}"
        f"{'cache_write':>13}{'output':>12}{'cost $':>11}"
    ]
    for stage, p in extrapolation.stages.items():
        lines.append(
            _usage_row(
                stage,
                round(p.measured.calls * p.output_factor),
                p.projected,
                p.cost,
            )
        )
    lines.append(f"{'TOTAL':<10}{'':>57}{extrapolation.cost:>11.2f}")
    return lines


def _derivation(extrapolation: Extrapolation) -> list[str]:
    factors = extrapolation.factors
    return [
        "",
        "multipliers, and where they came from",
        f"  {CHARS:<7}{factors[CHARS]:>7.2f}   {extrapolation.corpus_chars:,} corpus chars / "
        f"{extrapolation.pilot_chars:,} pilot chars",
        f"  {CALLS:<7}{factors[CALLS]:>7.2f}   {len(extrapolation.corpus)} corpus transcripts / "
        f"{len(extrapolation.piloted)} piloted",
        "",
        "  applied per stage:"
        + "".join(
            f"\n    {p.stage:<9} input x {p.input_factor:.2f} ({p.input_basis})"
            f"   output x {p.output_factor:.2f} ({CALLS})"
            for p in extrapolation.stages.values()
        ),
        "",
        "  The defender re-reads a whole transcript per call, so its input side follows",
        "  corpus size. Every other term is one note per call, so it follows the count.",
        "  A flat count on the defender's input is #55 and overstates it by 73% on the",
        "  current pair; characters on the attacker would understate it the same way.",
    ]


def _cache_table(rows: Sequence[Cache]) -> list[str]:
    lines = [
        "",
        "cache reads, per condition (pooled, one condition at zero is invisible)",
        f"{'stage':<10}{'cond':<7}{'records':>9}{'cache_read':>12}{'input side':>12}{'read %':>9}",
    ]
    for row in rows:
        lines.append(
            f"{row.stage:<10}{row.condition or '-':<7}{row.records:>9}"
            f"{row.read:>12}{row.total:>12}{row.ratio:>8.0%}"
        )
    return lines


def report(
    records: Sequence[RunRecord],
    sizes: Mapping[str, int],
    failures: Sequence[Failure] = (),
    *,
    budget: float = BUDGET,
) -> int:
    """Print the projection and return the gate's exit code.

    Non-zero means **do not launch the full run**: over budget, a note that
    failed, or a condition that never cached. A gate that exits 0 on an overrun
    is not a gate.
    """
    extrapolation = project(records, sizes)
    conditions, samples = len(defender.CONDITIONS), defender.SAMPLES
    print(
        f"pilot: {len(extrapolation.piloted)} of {len(extrapolation.corpus)} transcripts "
        f"({', '.join(extrapolation.piloted)})\n"
        f"       {extrapolation.pilot_chars:,} of {extrapolation.corpus_chars:,} chars, "
        f"{conditions} conditions x {samples} samples\n"
    )
    print("projected full run")
    for line in _projection_table(extrapolation) + _derivation(extrapolation):
        print(line)
    print(
        "\n  A defender record is one billed call; an attacker or control record is up to "
        f"{attacker.MAX_TURNS},\n  summed. The projection scales tokens, so the distinction "
        "does not reach the cost."
    )

    rows = cache_by_condition(records)
    for line in _cache_table(rows):
        print(line)
    print(_bias_note(extrapolation, sizes), end="")

    over = extrapolation.cost - budget
    verdict = (
        f"OVER by {over:,.2f}" if over > 0 else f"fits, with {-over:,.2f} of headroom"
    )
    # ASCII only, here and in `_bias_note`: this is printed to a console, and a
    # cp1252 terminal raises UnicodeEncodeError on the em dash the prose wants.
    print(f"\nprojected {extrapolation.cost:,.2f} against a ~{budget:,.2f} budget: {verdict}")
    if over > 0:
        print(
            "levers, least damaging first: attacker effort medium -> low; control arm on a\n"
            "stratified subset; n from 5 to 3; attacker to claude-sonnet-5, which costs the\n"
            "symmetry argument and turns T3 back into a lower bound."
        )

    problems = list(cache_warnings(rows))
    problems += [str(f) for f in failures]
    for problem in problems:
        print(f"\nwarning: {problem}")
    print(
        "\nstill owed by hand (#14): read three C1 notes. If they are not usable handoff\n"
        "notes, everything downstream measures nothing and no projection says so."
    )
    return 1 if problems or over > 0 else 0


# -------------------------------------------------------------------- the cli


def main(argv: list[str], root: Path = RUNS) -> int:
    """python -m src.pilot [--run] — report off `runs/`; `--run` spends.

    Reporting is the default because this is the first thing in the project that
    costs money. `--run` makes the pilot's billed calls and then reports on them.
    """
    if [a for a in argv if a != "--run"]:
        print("usage: python -m src.pilot [--run]", file=sys.stderr)
        return 2

    from src.transcript import load_all  # imported here: the report needs no fixture

    corpus = load_all()
    sizes = {t.id: len(t.rendered) for t in corpus}
    store = RunStore(root)
    failures: list[Failure] = []

    if "--run" in argv:
        import anthropic  # imported here so the deterministic tests never need the SDK

        from src.env import load_env
        from src.manifest import load as load_canaries
        from src.runs import git_sha

        load_env()
        missing = [t for t in PILOT if t not in sizes]
        if missing:
            print(f"unknown pilot transcript(s) {missing}", file=sys.stderr)
            return 1
        failures = run(
            {t.id: t.rendered for t in corpus if t.id in PILOT},
            anthropic.Anthropic(),
            store,
            canaries=load_canaries(),
            git_sha=git_sha(),
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    code = runs_report.main(root)
    records, _ = store.read_readable()
    if not records:
        # Not zero: the gate has reported no number, which is not the same as
        # having cleared. `--run` is what turns this into a measurement.
        print("\nthe pilot gate has not run: `python -m src.pilot --run` spends its calls")
        return 1
    print()
    return max(code, report(records, sizes, failures))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
