"""#14's gate: spend a measured amount, project the full run, then stop.

Two transcripts x three conditions x five samples, plus the attacker turns over
every note it writes and the control arm beside them. The *measured* usage then
comes back out of `runs/`, gets scaled to the full corpus, and is compared against
budget. It is a hard stop, not a task: nothing launches the full run until this
reports a number.

## What actually costs money, and what this therefore measures

The defender's whole input side is bounded above by ~$3.22 — 270 calls over a
~2,388-token prompt at full price — and about $0.57 once #10's cached prefix is
hitting. **Output tokens are the bill.** Thinking is on by default on Opus 5 and
bills at $25/MTok, so defender output is ~97% of the defender line, and the
attacker and control arms are output-dominated too. A projection that gets the
input side beautifully right and hand-waves the output term has aimed its
precision at about 1% of the budget.

So the term that decides the verdict is **how per-call output responds to
transcript length**, and this module measures it rather than assuming it. Let `e`
be the elasticity of a quantity to transcript length. The honest multiplier is

    F(e) = sum(L_i^e over the corpus) / sum(L_j^e over the pilot)

which is less a new idea than the general form of the two multipliers this gate
used to hardcode: **F(0) is the transcript count ratio and F(1) is the character
ratio.** Assuming a flat count is asserting `e = 0` without saying so. `e` is
fitted by regressing log mean output on log transcript length across the pilot
transcripts, which is why `PILOT` **spans** the corpus's length range instead of
sitting at one end of it: the fit needs a lever arm, and the pilot already
collects every number it needs.

Two elasticities are fitted, because two different things drive spend. The
defender's output follows the transcript it is reading (`thinking`). The attacker
and the control arm never see a transcript — they read a *note* — so their spend
follows note length, measured directly off the stored notes (`notes`) and far
better conditioned than a token count.

`e` is clamped to `[0, 1]`. Below zero would mean longer transcripts produce less
output, above one that they produce superlinearly more; either is a finding in
its own right rather than an input, and the clamp keeps the factor between the
two bases this gate would otherwise have had to choose between by hand.

## The verdict is a bound, not the fit

**The fitted interval is not a safety margin and must not be used as one.** With
two pilot transcripts the fit is *exact*, so the standard error propagated from
each transcript's 15 samples answers only "if these same two transcripts were
re-sampled, how far would the slope wobble". It captures no model
misspecification, no content–length confounding, and no between-transcript
variation — which at n=2 is the entire uncertainty. Monte Carlo over the real
pilot lengths with `e = 0` true by construction puts the fitted slope's actual
sd at 0.547 against a reported SE averaging 0.094: **6x narrow**, rising to 23x
at a cleaner within-transcript CV. The understatement gets *worse* as the
sampling gets cleaner, which is the exact inversion of what `±` means to a reader.
Worse, on the outcome this project expects — output proportional to length — the
fit clamps at both ends and prints a zero-width interval, which reads as
"confidently bracketed" and means "no interval was available".

So the budget comparison is `max` over the whole family the clamp can produce.
`_clamp` confines every fitted elasticity to `[0, 1]`, and `F(0)` and `F(1)` are
that interval's endpoints — so the bound needs no fit, no standard error and no
clamp to exist, and is never softer than the fit. `BOUND_ELASTICITIES` holds the
endpoints, `project` evaluates whole projections at each and takes the largest
cost rather than assuming which end is larger, and the fit is evaluated
alongside so the bound can never fall below it.

The fit is still computed, still printed, and still the honest number for #17.
It is simply not what the gate decides on.

Note which half of the clamp is dangerous: on this corpus `F` decreases in `e`,
so the **upper** clamp is conservative — a true `e = 1.5` projects 19% high and
`e = 2.0` projects 44% high. It is the **lower** clamp that would under-project,
and the bound is what removes its teeth.

## The input side, which is small but free to get right

`input_tokens` on a defender call is the *post-breakpoint* remainder — C2's
instruction and per-call structure — so it is a per-call constant and scales by
count, not by characters. The cached terms are neither: #10 deliberately caches
the note-format spec *together* with the transcript, so one prefix is `S + k*L`,
a count-scaled constant plus a chars-scaled variable that no single basis can
express. Two pilot transcripts of different lengths are two equations in two
unknowns, so `S` and `k` are **solved from the measured cache writes** and the
prefix factor follows exactly. That is the direct answer to "is there a term that
follows neither basis": yes, this one, and it is a second reason the pilot pair
must differ in length.

## What this gate cannot tell you

Printed with the number, because an unqualified projection is how the last three
defects in this project shipped — as plausible wrong numbers rather than crashes.

- **Length is confounded with content.** Two transcripts fit each elasticity, so
  anything that moves output and happens to correlate with length is inside `e`.
  The fit reports a standard error and the verdict is taken at the expensive end
  of it, but n=2 cannot separate the two and no arithmetic will.
- **A fallback silently becomes an assumption.** If a fit fails — equal lengths,
  a degenerate solve — the factor falls back to a flat count, which is `e = 0`
  asserted rather than measured. `Factor.measured` records which, the report says
  so, and the gate exits non-zero rather than letting it pass unread.
- **The control arm is projected on the observed note's elasticity.** A stripped
  note is shorter than the note it came from, most so where `RETENTION_FLOOR` is
  nearly tripped, and that gap is not modelled.
- **Refusals cost samples the projection does not replace.** A note the defender
  refuses is one fewer measurement, and the full run may refuse at another rate.
- **Attacker turn count varies** — a note that fails on turn 2 billed two turns —
  so the projection carries whatever failure rate 30 notes happened to show.
- **The cache regime is the 5-minute default**, which is the cheaper of the two
  here: one 1.25x write plus fourteen 0.1x reads is 2.65x base, against 3.4x for
  the 1-hour TTL. The residual risk is a *resumed* run, or a long backoff, pushing
  a gap past the window — every prefix re-written at 1.25x, which this projection
  does not model because the pilot ran inside it.
- **A mid-run settings change lands low.** `runs.exists()` keys on four
  coordinates, so relaunching after pulling an escalation lever keeps every record
  written under the old setting. `provenance_warnings` is folded into the gate's
  own problems for exactly that reason.
- **These are list prices.** `runs_report` says so; the bill is authoritative.
- **It says nothing about whether the notes are any good.** #14 also asks for a
  human read of three of them, and if C1's notes are garbage everything
  downstream measures nothing. That is not automatable and the report asks for it.

**Money is opt-in.** `python -m src.pilot` reports off `runs/` and calls nothing;
only `--run` spends. Resume is the store's: every stage skips what `runs/` already
holds, so a crash at call 23 of 30 re-pays for none of the first 22. A note the
defender refuses, the attacker fails on, or the control arm cannot strip is
collected and reported rather than raised — a gate that aborts on note 4 of 30 has
spent the money and reported nothing.
"""

import math
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from src import attacker, control, defender, runs_report
from src.attacker import AttackFailure
from src.control import StripError
from src.runs import RUNS, RunRecord, RunStore, Usage
from src.runs_report import StageTotals, price, provenance_warnings, summarise

# The pair #14 pilots: the corpus's **shortest and longest** transcripts. Not a
# projection input — `project` reads which transcripts actually ran off the
# records — but the span is what gives the elasticity fits a lever arm, and what
# makes the prefix model solvable at all. A pair of similar length degrades both
# to their fallbacks, loudly.
PILOT = ("internal_docs_link_rot", "refund_500_debug")

# CLAUDE.md, Budget: ~$18 defender + ~$36 attacker and control.
BUDGET = 55.00

# The four billed quantities, in `Usage`'s own field names.
TERMS = (
    "input_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
    "output_tokens",
)

CALLS = "calls"  # a per-call constant: F(0), the transcript count ratio
CHARS = "chars"  # strictly proportional to transcript length: F(1)
PREFIX = "prefix"  # #10's cached prefix, S + k*L, solved from the pilot
THINKING = "thinking"  # defender output: elasticity to transcript length, fitted
NOTES = "notes"  # attacker and control: elasticity of note length, fitted

# Which factor scales which term of which stage. The whole rule; a stage missing
# from it raises rather than defaulting to a basis nobody chose.
BASES = {
    defender.STAGE: {
        "input_tokens": CALLS,
        "cache_read_input_tokens": PREFIX,
        "cache_creation_input_tokens": PREFIX,
        "output_tokens": THINKING,
    },
    attacker.STAGE: dict.fromkeys(TERMS, NOTES),
    control.STAGE: dict.fromkeys(TERMS, NOTES),
}

# Below zero means longer transcripts produce less; above one, superlinearly more.
E_RANGE = (0.0, 1.0)

# The endpoints of the family `_clamp` can produce, and therefore the bound the
# verdict is read at. `F(0)` is the transcript count ratio and `F(1)` the
# character ratio, so this needs no fit and no standard error — which is the
# point, because the fit's standard error is a repeatability interval and far too
# narrow to be a safety margin (see the module docstring).
BOUND_ELASTICITIES = (0.0, 1.0)

# An SE at least this wide makes `±1 SE` cover the whole `[0, 1]` family, so the
# fit cannot tell a flat count from a proportional one and is reported as noise
# rather than as a measurement. This is the check `sxx <= 0` cannot make: that
# guard fires only on *exactly* equal lengths, while the condition that actually
# matters is a lever arm too short relative to the scatter.
UNINFORMATIVE_SE = 0.5

# #10's layout predicts 14 reads per write for the defender (93%) and 2 per 3
# turns for the attacker (67%). A third of the smaller only fires when caching is
# substantially broken rather than merely imperfect.
CACHE_FLOOR = 0.33


@dataclass(frozen=True)
class Failure:
    """A note the pilot could not distil, attack or strip. Collected, not raised."""

    stage: str
    condition: str
    transcript: str
    sample: int
    message: str

    def __str__(self) -> str:
        return f"{self.stage} {self.condition}/{self.transcript}/{self.sample}: {self.message}"


@dataclass(frozen=True)
class Factor:
    """One multiplier and — inseparably — where it came from.

    `measured` is False when a fit or a solve failed and the factor degraded to an
    assumption. #55 was a number that looked right and was 73% off with nothing in
    the output saying which multiplier produced it; a factor that cannot say how
    it was derived is the same defect wearing a different hat.
    """

    name: str
    value: float
    derivation: str
    measured: bool = True
    # False when the fit exists but its standard error is too wide to distinguish
    # a flat count from a proportional one. Not a safety problem — the verdict is
    # a bound over the whole family either way — but a fit that says nothing must
    # not be printed as though it said something.
    informative: bool = True


@dataclass(frozen=True)
class Projection:
    """One stage's measured spend, and the same stage scaled to the full corpus."""

    stage: str
    model: str
    measured: StageTotals
    bases: dict[str, str]
    projected: Usage
    cost: float


@dataclass(frozen=True)
class Extrapolation:
    """Every stage's projection, the factors behind it, and the fits' own spread."""

    piloted: tuple[str, ...]
    corpus: tuple[str, ...]
    pilot_chars: int
    corpus_chars: int
    factors: dict[str, Factor]
    stages: dict[str, Projection]
    # Every candidate the verdict is bounded over, label -> total cost: the fit,
    # the fit shifted one standard error each way, and the endpoints of the family
    # `_clamp` can produce. Evaluated, never assumed — which end is larger is a
    # property of the corpus, not something this module gets to declare.
    candidates: dict[str, float]

    @property
    def cost(self) -> float:
        """The fitted projection. The honest central number, and not the verdict."""
        return sum(p.cost for p in self.stages.values())

    @property
    def bound(self) -> float:
        """What the budget is compared against — see the module docstring.

        Never below `cost`, because the fit is one of the candidates.
        """
        return max(self.candidates.values())

    @property
    def assumed(self) -> tuple[Factor, ...]:
        """Factors that fell back to an assumption instead of a measurement."""
        return tuple(f for f in self.factors.values() if not f.measured)

    @property
    def uninformative(self) -> tuple[Factor, ...]:
        """Fits too noisy to distinguish a flat count from a proportional one."""
        return tuple(f for f in self.factors.values() if f.measured and not f.informative)


@dataclass(frozen=True)
class Cache:
    """One group's input side, split by how it was billed."""

    stage: str
    axis: str  # "condition" or "transcript"
    group: str
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

    **Every recoverable failure is collected, not raised.** A refused note, a
    failed attack and a note too dense to strip each already wrote a record
    carrying what it billed (#10, #11, #12), and a gate that aborts on note 4 of
    30 has spent the money and reported nothing. A *truncated* note is the one
    exception and propagates, because it says `MAX_TOKENS` is wrong for this
    corpus and 29 more calls under a known-broken ceiling is not a measurement.
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
            on_refusal=lambda condition, sample, exc, t=transcript: failures.append(
                Failure(defender.STAGE, condition, t, sample, str(exc))
            ),
        )
        for condition in conditions:
            for sample in range(samples):
                record = store.read(defender.STAGE, condition, transcript, sample)
                if record is None:
                    raise RuntimeError(
                        f"no defender record at {condition}/{transcript}/{sample} "
                        "after writing it: the store disagrees with itself"
                    )
                if defender.failed(record):
                    continue  # nothing was distilled, so there is no note to attack
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


# ---------------------------------------------------------- fitting the factors


def _mean_sem(values: Sequence[float]) -> tuple[float, float]:
    """Sample mean, and the standard error of that mean."""
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    return mean, math.sqrt(variance / n)


def _elasticity(points: Mapping[int, Sequence[float]]) -> tuple[float, float] | None:
    """Fit `e` in `y = c * L^e`, and the standard error of `e`.

    Ordinary least squares of `ln(mean y)` on `ln(L)`, one point per pilot
    transcript. The slope *is* the elasticity, and `c` never has to be estimated
    because it cancels out of `F(e)`.

    `se` is propagated from each point's own within-transcript standard error
    rather than from the residuals: with two transcripts the fit is exact and has
    no residual to learn from, but each point has 15 samples behind it and that is
    where the uncertainty actually lives.

    None when there is nothing to fit — fewer than two transcripts, every pilot
    transcript the same length, or a non-positive measurement. The caller then
    falls back to a flat count and says so.
    """
    xs, ys, relative_variance = [], [], []
    for length, values in points.items():
        if length <= 0 or not values:
            return None
        mean, sem = _mean_sem(values)
        if mean <= 0:
            return None
        xs.append(math.log(length))
        ys.append(math.log(mean))
        relative_variance.append((sem / mean) ** 2)
    if len(xs) < 2:
        return None
    xbar = sum(xs) / len(xs)
    sxx = sum((x - xbar) ** 2 for x in xs)
    # No lever arm at all: every piloted transcript the same length. This is the
    # last line before a division by `sxx`, and it is *not* the check that keeps
    # the fit honest — it fires only on exactly equal log-lengths, while the
    # hazard that bites is a lever arm too short relative to the scatter (two
    # transcripts 53 chars apart fit e = +6.25 +/- 6.81, clamp silently, and
    # report `measured`). `UNINFORMATIVE_SE` flags that, and
    # `test_the_pilot_pair_spans_the_corpus` is what keeps it latent: widen
    # `PILOT` off the corpus's endpoints and it goes live.
    if sxx <= 0:
        return None
    slope = sum((x - xbar) * y for x, y in zip(xs, ys)) / sxx
    se = math.sqrt(sum(((x - xbar) / sxx) ** 2 * v for x, v in zip(xs, relative_variance)))
    return slope, se


def _elastic(sizes: Mapping[str, int], piloted: Sequence[str], e: float) -> float:
    """`F(e)` — the corpus's summed `L^e` over the pilot's.

    `F(0)` is the transcript count ratio and `F(1)` the character ratio, so the
    two multipliers this gate used to hardcode are the endpoints of this one.
    """
    return sum(length**e for length in sizes.values()) / sum(sizes[t] ** e for t in piloted)


def _prefix_model(
    sizes: Mapping[str, int], writes: Mapping[str, int]
) -> tuple[float, float] | None:
    """Solve `prefix(L) = S + k*L` from the pilot's measured cache writes.

    #10 caches the note-format spec together with the transcript, so a prefix is a
    count-scaled constant plus a chars-scaled variable and neither basis alone can
    express it. Two transcripts of different lengths are two equations.

    The write per transcript is the **largest** single record's, not the sum: one
    prefix is written once per transcript by design, and a TTL expiry mid-run adds
    a second write that says nothing about the prefix's size.

    None on a degenerate solve — equal lengths, or a fit implying a prefix that
    shrinks with length or has negative fixed cost — which means the measurement
    is too noisy to trust and the caller falls back to the character ratio.
    """
    points = sorted((sizes[t], w) for t, w in writes.items())
    if len(points) < 2:
        return None
    (short_len, short_write), (long_len, long_write) = points[0], points[-1]
    if long_len == short_len:
        return None
    k = (long_write - short_write) / (long_len - short_len)
    spec = short_write - k * short_len
    if k <= 0 or spec < 0:
        return None
    return spec, k


@dataclass(frozen=True)
class Measurements:
    """What the pilot's records say about how spend responds to length."""

    output_tokens: dict[int, list[float]]  # transcript length -> per-call output
    note_chars: dict[int, list[float]]  # transcript length -> per-note characters
    prefix_writes: dict[str, int]  # transcript -> its one cached-prefix write


def _measurements(records: Sequence[RunRecord], sizes: Mapping[str, int]) -> Measurements:
    """Read the fits' inputs off the defender's records.

    Failure records are excluded from both fits: they carry no note, and their
    output tokens are whatever a refusal cost rather than a measurement of how
    much a transcript of that length makes the model write.
    """
    output: dict[int, list[float]] = {}
    notes: dict[int, list[float]] = {}
    writes: dict[str, int] = {}
    for r in records:
        if r.stage != defender.STAGE:
            continue
        writes[r.transcript] = max(
            writes.get(r.transcript, 0), r.usage.cache_creation_input_tokens
        )
        if defender.failed(r):
            continue
        length = sizes[r.transcript]
        output.setdefault(length, []).append(r.usage.output_tokens)
        notes.setdefault(length, []).append(len(r.output))
    return Measurements(output, notes, writes)


def _clamp(e: float) -> float:
    return min(max(e, E_RANGE[0]), E_RANGE[1])


def _fitted(
    name: str,
    sizes: Mapping[str, int],
    piloted: Sequence[str],
    estimate: tuple[float, float] | None,
    shift: float,
    override: float | None,
) -> Factor | None:
    """One fitted factor, or `None` when there was nothing to fit.

    `override` holds `e` at a named value for one of the bound's candidates, and
    deliberately bypasses both the fit and the fallback: the bound is over every
    elasticity the clamp *could* produce, whether or not this run managed to
    measure one.
    """
    if override is not None:
        return Factor(
            name,
            _elastic(sizes, piloted, override),
            f"e held at {override:.2f} for the conservative bound",
        )
    if estimate is None:
        return None
    e, se = estimate
    used = _clamp(e + shift * se)
    return Factor(
        name,
        _elastic(sizes, piloted, used),
        f"elasticity {e:+.2f} +/- {se:.2f}, used {used:.2f}; sum(L^e) corpus / pilot",
        informative=se <= UNINFORMATIVE_SE,
    )


def _factors(
    sizes: Mapping[str, int],
    piloted: Sequence[str],
    measurements: Measurements,
    shift: float = 0.0,
    override: float | None = None,
) -> dict[str, Factor]:
    """Every multiplier, measured where the pilot supports it and flagged where not."""
    corpus_chars, pilot_chars = sum(sizes.values()), sum(sizes[t] for t in piloted)
    calls = Factor(
        CALLS,
        len(sizes) / len(piloted),
        f"{len(sizes)} corpus transcripts / {len(piloted)} piloted",
    )
    chars = Factor(
        CHARS,
        corpus_chars / pilot_chars,
        f"{corpus_chars:,} corpus chars / {pilot_chars:,} pilot chars",
    )

    solved = _prefix_model(sizes, measurements.prefix_writes)
    if solved is None:
        prefix = replace(
            chars,
            name=PREFIX,
            measured=False,
            derivation=chars.derivation + "; prefix model unsolved, assuming pure chars",
        )
    else:
        spec, k = solved
        prefix = Factor(
            PREFIX,
            sum(spec + k * length for length in sizes.values())
            / sum(spec + k * sizes[t] for t in piloted),
            f"prefix = {spec:,.0f} + {k:.3f}/char, solved from measured cache writes",
        )

    def fallback(name: str, why: str) -> Factor:
        return replace(calls, name=name, measured=False, derivation=f"{calls.derivation}; {why}")

    thinking = _fitted(
        THINKING, sizes, piloted, _elasticity(measurements.output_tokens), shift, override
    )
    notes = _fitted(
        NOTES, sizes, piloted, _elasticity(measurements.note_chars), shift, override
    )
    return {
        CALLS: calls,
        CHARS: chars,
        PREFIX: prefix,
        THINKING: thinking or fallback(THINKING, "no fit, assuming output is flat per call"),
        NOTES: notes or fallback(NOTES, "no fit, assuming note length is flat per call"),
    }


# ------------------------------------------------------------- the projection


def _stages(records: Sequence[RunRecord], factors: Mapping[str, Factor]) -> dict[str, Projection]:
    stages = {}
    for stage, totals in summarise(records).items():
        models = sorted({r.model for r in records if r.stage == stage})
        if len(models) != 1:
            # Not a warning. Scaling one number off two models' rates produces a
            # dollar figure that belongs to neither.
            raise ValueError(f"{stage} mixes models {models}: cannot project one cost")
        bases = BASES.get(stage)
        if bases is None:
            raise ValueError(
                f"{stage!r} has no entry in BASES; add one rather than letting it "
                "default to a basis nobody chose"
            )
        # Rounded: a projected token count is still a count, and a fractional
        # token in a `Usage` would be a lie about the field it sits in.
        projected = Usage(
            **{term: round(getattr(totals, term) * factors[bases[term]].value) for term in TERMS}
        )
        stages[stage] = Projection(
            stage=stage,
            model=models[0],
            measured=totals,
            bases=bases,
            projected=projected,
            cost=price(projected, models[0]),
        )
    return stages


def project(records: Sequence[RunRecord], sizes: Mapping[str, int]) -> Extrapolation:
    """Scale the pilot's measured spend to the whole corpus.

    `sizes` is the corpus, transcript id -> rendered chars. The pilot's own share
    is derived from the records — which transcripts the defender actually ran —
    rather than read off `PILOT`, so switching the pilot pair moves every factor
    with it and cannot leave a stale constant behind (#55).

    `candidates` re-runs the whole projection at the fit, at the fit shifted one
    standard error each way, and at each endpoint of the family `_clamp` can
    produce. The verdict is the largest of them — see the module docstring on why
    the fitted interval is not a safety margin.
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

    measured = _measurements(records, sizes)
    factors = _factors(sizes, piloted, measured)
    stages = _stages(records, factors)

    def total(**kwargs) -> float:
        candidate = _factors(sizes, piloted, measured, **kwargs)
        return sum(p.cost for p in _stages(records, candidate).values())

    # The point estimate is a candidate in its own right, and not because it is
    # a convenient label for the central number. `F` need not be monotone in
    # `e`: bunch the corpus in the middle and put the pilot at the extremes and
    # it acquires an interior maximum -- 16 transcripts at 10,000 chars piloted
    # at (500, 20,000) gives F(0) = 9.000 and F(1) = 8.805 with a peak of 10.869
    # near e = 0.40, so neither the endpoints nor a band around the fit covers
    # the fit. On *this* corpus `F` decreases in `e` and the endpoints do cover
    # everything, but that is a property of the corpus rather than of the
    # arithmetic, and the bound must not rest on it silently.
    candidates = {"fit": sum(p.cost for p in stages.values())}
    candidates["fit -1 SE"] = total(shift=-1.0)
    candidates["fit +1 SE"] = total(shift=1.0)
    for e in BOUND_ELASTICITIES:
        candidates[f"e = {e:.2f}"] = total(override=e)

    return Extrapolation(
        piloted=tuple(piloted),
        corpus=tuple(sorted(sizes)),
        pilot_chars=sum(sizes[t] for t in piloted),
        corpus_chars=sum(sizes.values()),
        factors=factors,
        stages=stages,
        candidates=candidates,
    )


# ------------------------------------------------------------------ the cache


def _rows(records: Sequence[RunRecord], axis: str, key) -> tuple[Cache, ...]:
    groups: dict[tuple[str, str], list[RunRecord]] = {}
    for r in records:
        groups.setdefault((r.stage, key(r)), []).append(r)
    return tuple(
        Cache(
            stage=stage,
            axis=axis,
            group=group,
            records=len(rs),
            uncached=sum(r.usage.input_tokens for r in rs),
            read=sum(r.usage.cache_read_input_tokens for r in rs),
            written=sum(r.usage.cache_creation_input_tokens for r in rs),
        )
        for (stage, group), rs in sorted(groups.items())
    )


def cache_rows(records: Sequence[RunRecord]) -> tuple[Cache, ...]:
    """Both groupings, because the two answer different questions.

    The attacker's prefix is the note, so its cache behaviour is a property of the
    **condition**: C3's scrubbed notes are the shortest artefacts in the pipeline
    and the ones that can fall under Opus 5's minimum cacheable prefix.

    The defender's prefix is the **transcript** — #10 caches one per transcript
    across all 15 of its calls — so condition rows say nothing about it. A run
    where one transcript caches perfectly and another never caches at all shows
    three identical, healthy-looking condition rows. #14 asks for a non-zero read
    *after the first call per transcript*, and only the transcript grouping
    answers that.
    """
    return _rows(records, "condition", lambda r: r.condition) + _rows(
        records, "transcript", lambda r: r.transcript
    )


def cache_warnings(rows: Sequence[Cache], floor: float = CACHE_FLOOR) -> list[str]:
    """One line per group whose cache is not doing its job.

    A **ratio** floor, not `read == 0`: #10's layout predicts 14 reads per write
    for the defender, so a cache limping along at 1% of its input side is as
    broken as one at 0% and used to be silent. Groups of one record are exempt —
    the first call has to write before anything can read.

    The cause is deliberately left open. A prefix under Opus 5's 512-token minimum
    is one candidate; something volatile in the prefix, or a gap longer than the
    5-minute TTL, produce the same row and want different fixes.
    """
    return [
        f"{row.stage} {row.axis}={row.group} read {row.ratio:.0%} of its input side "
        f"across {row.records} records, under the {floor:.0%} floor: the prefix is "
        "mostly missing (too short to cache, volatile, or expired between calls), "
        "and an uncached prefix costs about ten times a cached one"
        for row in rows
        if row.records > 1 and row.ratio < floor
    ]


# ----------------------------------------------------------------- the report


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
    calls = extrapolation.factors[CALLS].value
    for p in extrapolation.stages.values():
        lines.append(_usage_row(p.stage, round(p.measured.calls * calls), p.projected, p.cost))
    lines.append(f"{'TOTAL':<10}{'':>57}{extrapolation.cost:>11.2f}")
    return lines


def _derivation(extrapolation: Extrapolation) -> list[str]:
    lines = ["", "multipliers, and where each came from"]
    for factor in extrapolation.factors.values():
        flag = "" if factor.measured else "   [ASSUMED, not measured]"
        lines.append(f"  {factor.name:<9}{factor.value:>7.2f}   {factor.derivation}{flag}")
    lines += ["", "  applied per stage and per term:"]
    for p in extrapolation.stages.values():
        for term in TERMS:
            lines.append(
                f"    {p.stage:<9} {term:<28} x "
                f"{extrapolation.factors[p.bases[term]].value:>5.2f}  ({p.bases[term]})"
            )
    lines += [
        "",
        "  Output tokens are the bill: thinking bills at $25/MTok, and the defender's",
        "  whole input side is bounded above by ~$3.22 even with the cache never hitting.",
        "  So the output terms scale by a *fitted* elasticity to transcript length rather",
        "  than a flat count. F(0) is the count ratio and F(1) the character ratio, so",
        "  picking either without measuring is asserting e=0 or e=1 in silence.",
    ]
    return lines


def _cache_table(rows: Sequence[Cache]) -> list[str]:
    lines = [
        "",
        "cache reads, per condition and per transcript (the defender's prefix is per",
        "transcript, so only the second grouping answers #14's check)",
        f"{'stage':<10}{'axis':<11}{'group':<30}{'records':>8}{'cache_read':>12}"
        f"{'input side':>12}{'read %':>8}",
    ]
    for row in rows:
        lines.append(
            f"{row.stage:<10}{row.axis:<11}{row.group:<30}{row.records:>8}"
            f"{row.read:>12}{row.total:>12}{row.ratio:>7.0%}"
        )
    return lines


def _span_note(extrapolation: Extrapolation, sizes: Mapping[str, int]) -> str:
    """The pilot pair's shape, in the one sentence it is worth.

    Deliberately short. An earlier draft argued at length that a longer pilot pair
    biases the cache ratio; the read:write ratio is 14:1 because 15 calls share one
    prefix *by design*, and length moves it across the whole corpus by about a
    tenth of a percentage point — while `transcript.MIN_CHARS` rules out the one
    length effect that would matter, falling under the 512-token floor. What length
    actually biases is the count-scaled terms, and those are now fitted rather than
    assumed. So all that is left to say is what the pair spans, and what still
    rests on an assumption.
    """
    lengths = sorted(sizes[t] for t in extrapolation.piloted)
    mean = extrapolation.corpus_chars / len(extrapolation.corpus)
    line = (
        f"\npilot pair spans {lengths[0]:,}-{lengths[-1]:,} chars against a corpus mean of "
        f"{mean:,.0f};\nthat span is the lever arm every fitted elasticity is measured over.\n"
    )
    if extrapolation.assumed:
        line += (
            "Falling back to a flat count on: "
            + ", ".join(f.name for f in extrapolation.assumed)
            + ".\nThose terms are projected on an assumption this pilot did not test.\n"
        )
    return line


def report(
    records: Sequence[RunRecord],
    sizes: Mapping[str, int],
    failures: Sequence[Failure] = (),
    *,
    budget: float = BUDGET,
) -> int:
    """Print the projection and return the gate's exit code.

    Non-zero means **do not launch the full run**: the conservative bound is over
    budget, a note failed, a factor fell back to an assumption or fitted only
    noise, a stage drifted in model, effort or prompt, or a group barely read its
    cache. A gate that exits 0 on an overrun is not a gate.
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

    rows = cache_rows(records)
    for line in _cache_table(rows):
        print(line)
    print(_span_note(extrapolation, sizes), end="")

    bound = extrapolation.bound
    over = bound - budget
    verdict = f"OVER by {over:,.2f}" if over > 0 else f"fits, with {-over:,.2f} of headroom"
    # ASCII only, here and above: this prints to a console, and a cp1252 terminal
    # raises UnicodeEncodeError on the em dash the prose wants.
    print(f"\nprojected {extrapolation.cost:,.2f} at the fitted elasticities.")
    print(f"conservative bound {bound:,.2f}, the largest cost over the whole clamped family:")
    for label, cost in extrapolation.candidates.items():
        marker = "  <-- bound" if cost == bound else ""
        print(f"  {label:<12}{cost:>10,.2f}{marker}")
    print(
        "\n  The verdict is the bound, not the fit. With two pilot transcripts the fit is\n"
        "  exact, so its standard error only answers 'how far would the slope wobble if\n"
        "  these same two transcripts were re-sampled' -- it captures no confounding and\n"
        "  no between-transcript variation, which at n=2 is the whole uncertainty. It runs\n"
        "  ~6x narrow at a realistic within-transcript CV and ~23x narrow at a clean one,\n"
        "  and it collapses to zero width on the outcome this project expects. The clamp\n"
        "  confines every multiplier to F(e) over e in [0, 1], so the endpoints bound the\n"
        "  family for free -- no fit, no standard error, never softer than the fit."
    )
    print(f"\nAgainst a ~{budget:,.2f} budget, read at the bound: {verdict}")
    if over > 0:
        print(
            "levers, least damaging first: attacker effort medium -> low; control arm on a\n"
            "stratified subset; n from 5 to 3; attacker to claude-sonnet-5, which costs the\n"
            "symmetry argument and turns T3 back into a lower bound."
        )

    problems = [
        f"{f.name} fell back to an assumption: {f.derivation}" for f in extrapolation.assumed
    ]
    problems += [
        f"{f.name} fit is noise, not a measurement ({f.derivation}): +/-1 SE covers the "
        "whole [0, 1] family, so the lever arm is too short relative to the scatter to "
        "tell a flat count from a proportional one"
        for f in extrapolation.uninformative
    ]
    problems += cache_warnings(rows)
    # The ladder's first rung is re-running at a lower effort, and `runs.exists()`
    # keys on four coordinates — so it keeps every record written under the old
    # setting and the re-measured cost lands low, the reassuring direction.
    problems += provenance_warnings(tuple(records))
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
