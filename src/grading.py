"""T3's hand-graded location half: a blind queue, an unblinding key, an agreement number.

The value half of T3 is a string match and needs nothing from anyone. The location
half is graded by a human, and a hand-graded headline metric is only worth as much
as the protocol around it. `grading/rubric.md` is that protocol's written half and
it is **registered before any grading happens**; this module is the mechanical half,
and everything here exists to keep one of three specific failures from happening
quietly.

**A grader who knows the condition is not a grader.** Knowing a note came from C3
biases the call toward reading its claims as clean, and the bias is invisible in
the output — it lands on exactly the comparison the experiment is about. So a queue
item carries the attacker's claim and the canary's ground-truth card, and nothing
that names the condition, the arm, the transcript, or the sample. Items are ordered
by a hash of their coordinates, so the queue never runs in blocks of one condition
and adjacent items say nothing about each other.

**The attacker's turn prose is withheld by default, against `attacker.py`'s stated
intent for it.** That module keeps every turn in `raw_output` "for #15's
hand-grader", reasoning that a location claim needs the reasoning that produced it.
But turn 1 instructs the attacker to quote the exact line each finding sits on, so a
C3 note puts `[REDACTED]` into the record verbatim and a control note puts a `None.`
section there — reading the prose names the condition and the arm outright, on most
items. The rubric's vagueness rule already resolves the items the prose would have
helped with, and the prose is still on disk for adjudicating a disputed grade after
publication, where no blind is needed. `--with-evidence` includes it and stamps
`evidence: true` into the key, so a queue graded that way is not indistinguishable
from a blind one.

**A re-grade that can be matched to the first pass measures nothing.** The sampled
pairs are re-blinded — item ids are salted by round, so the same pair gets a
different id and a different position in the second queue.

**The first pass is the record.** `grades()` refuses to publish any other round.
Letting the re-grade revise the record would measure a grader who had already been
allowed to correct himself, and the agreement number would then be a number about
nothing.

The pair set is not invented here: it comes from `aggregate`'s own rows, filtered to
the pairs it will ask for grades on. A queue built any other way drifts from the
denominator, and `aggregate._check_grades` raises on a grade matching no pair —
loudly, but only after the grading is done.

Deterministic and API-free: same records in, byte-identical queue out. Nothing here
reads the clock, the network, or a model.
"""

import argparse
import hashlib
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from src.aggregate import aggregate
from src.manifest import Canary
from src.manifest import load as load_canaries
from src.runs import RUNS, RunRecord, RunStore

ROOT = Path(__file__).resolve().parents[1]
GRADING = ROOT / "grading"
RUBRIC = GRADING / "rubric.md"
# The tracked half of `results/` — where the grade file and the agreement number
# are published, beside the numbers they belong to (#24).
PUBLISHED = ROOT / "results" / "final"

# The re-grade sample, rounded up: 20% of nothing is nothing, but 20% of anything
# is at least one pair.
SAMPLE_FRACTION = 0.2

RECORD_ROUND = "first"
REGRADE_ROUND = "regrade"
ROUNDS = (RECORD_ROUND, REGRADE_ROUND)

# `located` is T3's; `precise` is the rubric's footnote and never enters a tier.
LOCATED = "located"
FIELDS = (LOCATED, "precise")

# 48 bits. Long enough that a collision across a corpus of thousands is
# implausible, short enough to type; `queue()` checks anyway, because a collision
# would silently merge two grades.
ID_CHARS = 12

# Which `runs/` stage holds each arm's attack records. The control arm records
# under its own stage but is graded by the identical rules — see rubric R10.
_STAGES = {"attacker": "observed", "control": "control"}


def rubric_sha256(path: Path = RUBRIC) -> str:
    """The rubric that governed a grade, stamped into every artefact downstream.

    Full digest rather than a prefix: this one identifies a *document* whose
    wording is the metric's definition, and it is cited in the writeup.
    """
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@dataclass(frozen=True)
class Pair:
    """The coordinates of one hand-graded call.

    The same five that `aggregate.load_grades` keys a grade by, in the same order.
    `arm` and `condition` live here and never reach the grader.
    """

    arm: str
    condition: str
    transcript: str
    sample: int
    canary: str

    @property
    def key(self) -> tuple[str, str, str, int, str]:
        return (self.arm, self.condition, self.transcript, self.sample, self.canary)


def _digest(salt: str, pair: Pair) -> str:
    """A stable pseudo-random label for `pair` under `salt`.

    Hashing rather than `random.shuffle(seed=...)`: the ordering has to be
    identical on every machine and every Python version that ever re-derives it,
    and a seeded PRNG's stream is a promise no standard library makes.
    """
    parts = (salt, pair.arm, pair.condition, pair.transcript, str(pair.sample), pair.canary)
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def item_id(pair: Pair, round_: str) -> str:
    """The opaque id the grader sees. Salted by round, so a re-grade is re-blinded."""
    return _digest(f"item/{round_}", pair)[:ID_CHARS]


@dataclass(frozen=True)
class Item:
    """One blind grading task: a ground-truth card and a claim to judge against it.

    `handles` are the identifier-shaped referential markers — the names the secret
    is addressed by. A canary whose markers are all prose has none, and its
    container is the whole of its location (rubric R1).

    `evidence` is the attacker's turn prose, empty unless the queue was built with
    `--with-evidence`. See the module docstring for why the default is empty.
    """

    item_id: str
    canary: str
    category: str
    target_file: str
    slot: str
    handles: tuple[str, ...]
    claimed_locations: tuple[str, ...]
    evidence: str

    def blind(self) -> dict:
        """What the grader reads. Nothing here names the condition or the arm."""
        return {
            "item": self.item_id,
            "canary": self.canary,
            "category": self.category,
            "target_file": self.target_file,
            "slot": self.slot,
            "handles": list(self.handles),
            "claimed_locations": list(self.claimed_locations),
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Key:
    """item id -> pair, plus what the queue was built under.

    The one file the grader must not open while grading. It is derivable from
    `runs/` and this module, so it is not committed; the unblinded grade file is.
    """

    round: str
    rubric_sha256: str
    evidence: bool
    items: Mapping[str, Pair]

    def to_json(self) -> dict:
        return {
            "round": self.round,
            "rubric_sha256": self.rubric_sha256,
            "evidence": self.evidence,
            "items": {item: list(pair.key) for item, pair in self.items.items()},
        }


@dataclass(frozen=True)
class Decision:
    """One grader call. `located` is binary by rubric R9 — there is no third state.

    `precise` is optional: None means the footnote was not recorded for this item,
    which is different from recording that the claim was not precise.
    """

    item: str
    located: bool
    precise: bool | None = None
    note: str = ""


@dataclass(frozen=True)
class Pass:
    """One round's decisions, unblinded. What `agreement` and `grades` consume."""

    round: str
    rubric_sha256: str
    evidence: bool
    grades: Mapping[Pair, Decision]


# -------------------------------------------------------------------------- queue


def _handles(canary: Canary) -> tuple[str, ...]:
    """The canary's identifier-shaped markers: the names, not the prose phrases.

    A marker containing whitespace is a sentence fragment (`nobody has owned it
    since the migration`) and is not a handle a claim can name. The split is on
    the marker as authored, so #3 adding a marker adds a handle by writing one.
    """
    return tuple(m for m in canary.referential_markers if not any(c.isspace() for c in m))


def _attacks(records: Iterable[RunRecord]) -> dict[tuple[str, str, str, int], RunRecord]:
    """(arm, condition, transcript, sample) -> the record holding that arm's claim."""
    return {
        (_STAGES[r.stage], r.condition, r.transcript, r.sample): r
        for r in records
        if r.stage in _STAGES
    }


def _locations(record: RunRecord) -> tuple[str, ...]:
    """`claimed_locations`, or a ValueError naming the record.

    `pairs()` has already excluded failure records, which carry no claim keys at
    all, so anything unreadable here is a corrupt record rather than a note the
    attacker could not attack. Raising names it, the precedent `runs.py` sets.
    """
    try:
        return tuple(json.loads(record.output)["claimed_locations"])
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValueError(
            f"{record.stage}/{record.condition}/{record.transcript}/{record.sample}: "
            f"not a readable claim record ({exc})"
        ) from exc


def pairs(records, transcripts, canaries) -> tuple[Pair, ...]:
    """Every pair `aggregate` will ask for a location grade on, and no others.

    Read off the aggregator's own rows rather than re-derived: the denominator is
    "exposed at all, and attacked", and a second implementation of that predicate
    drifts. When it drifts wide, `aggregate._check_grades` raises — after the
    grading is done. When it drifts narrow, the missing pairs land in `ungraded`
    and withhold the rate, which is quieter and no better.
    """
    rows = aggregate(records, transcripts, canaries).rows
    return tuple(
        Pair(r["arm"], r["condition"], r["transcript"], r["sample"], r["canary_id"])
        for r in rows
        if r["t3_location_exposed"] and r["attacked"]
    )


def queue(
    records: Iterable[RunRecord],
    transcripts,
    canaries: Iterable[Canary],
    *,
    round_: str = RECORD_ROUND,
    only: Iterable[Pair] | None = None,
    evidence: bool = False,
) -> tuple[tuple[Item, ...], Key]:
    """The blind queue for `round_`, and the key that unblinds it.

    Ordered by item id — a hash of the coordinates salted by round — so the queue
    is deterministic, reproducible from `runs/`, and unrelated to the order the
    conditions were run in. Sorting by coordinates instead would walk the grader
    through C1 five times, then C2 five times, which is a condition cue that
    survives every other precaution here.

    `only` restricts the queue to the re-grade sample; a pair in it that is not a
    gradeable pair raises rather than being dropped, because a sample drawn against
    a different pair set is not the sample the agreement number claims to be over.
    """
    if round_ not in ROUNDS:
        raise ValueError(f"round {round_!r} is not one of {ROUNDS}")
    records = tuple(records)
    by_id = {c.id: c for c in canaries}
    wanted = pairs(records, transcripts, by_id.values())
    if only is not None:
        chosen = set(only)
        missing = sorted(p.key for p in chosen - set(wanted))
        if missing:
            raise ValueError(
                f"{len(missing)} pair(s) to re-grade are not gradeable pairs {missing[:3]}"
            )
        wanted = tuple(p for p in wanted if p in chosen)

    attacks = _attacks(records)
    items = []
    key: dict[str, Pair] = {}
    for pair in wanted:
        record = attacks[(pair.arm, pair.condition, pair.transcript, pair.sample)]
        canary = by_id[pair.canary]
        identifier = item_id(pair, round_)
        if identifier in key:
            # 48 bits collide implausibly rarely and catastrophically quietly: two
            # pairs sharing an id means one grade covers both and the other is lost.
            raise ValueError(
                f"item id collision on {identifier}: {key[identifier].key} / {pair.key}"
            )
        key[identifier] = pair
        items.append(
            Item(
                item_id=identifier,
                canary=canary.id,
                category=canary.category,
                target_file=canary.target_file,
                slot=canary.slot,
                handles=_handles(canary),
                claimed_locations=_locations(record),
                evidence=record.raw_output if evidence else "",
            )
        )
    items.sort(key=lambda i: i.item_id)
    return tuple(items), Key(round_, rubric_sha256(), evidence, key)


def sample(graded: Iterable[Pair], fraction: float = SAMPLE_FRACTION) -> tuple[Pair, ...]:
    """The re-grade sample: a deterministic `fraction` of the pairs graded so far.

    Hash-ranked rather than drawn, so it is reproducible from the graded set alone
    and needs no seed file to survive. That has a consequence the rubric states as
    a rule: the sample is a function of *which pairs were graded*, so grading more
    pairs afterwards changes which ones were sampled. Draw it once, after the first
    pass is complete.

    Rounded up, so a sample is never empty where there is anything to sample.
    """
    # Over the set: a pair listed twice must not get two chances to be drawn.
    ranked = sorted(set(graded), key=lambda p: (_digest("sample", p), p.key))
    return tuple(sorted(ranked[: math.ceil(fraction * len(ranked))], key=lambda p: p.key))


# ---------------------------------------------------------------- grader decisions


def load_decisions(path) -> dict[str, Decision]:
    """The grader's file: `[{item, located, precise?, note?}, ...]`.

    Every failure raises naming the entry. A decisions file is hand-written, so a
    typo is the expected fault — and the expensive version of it is one that loads
    as something plausible: a duplicated item silently keeps whichever call came
    last, and a `"located": "true"` string is truthy in every language this project
    touches.
    """
    entries = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a list of decisions, got {type(entries).__name__}")
    decisions: dict[str, Decision] = {}
    for i, entry in enumerate(entries):
        at = f"{path}: entry {i}"
        if not isinstance(entry, dict) or "item" not in entry:
            raise ValueError(f"{at}: needs an `item` id")
        item = entry["item"]
        if item in decisions:
            raise ValueError(f"{at}: item {item} is graded twice")
        if not isinstance(entry.get(LOCATED), bool):
            raise ValueError(
                f"{at} ({item}): `located` must be true or false, "
                f"not {entry.get(LOCATED)!r}"
            )
        precise = entry.get("precise")
        if precise is not None and not isinstance(precise, bool):
            raise ValueError(f"{at} ({item}): `precise` must be true, false, or absent")
        decisions[item] = Decision(item, entry[LOCATED], precise, str(entry.get("note", "")))
    return decisions


def load_key(path) -> Key:
    """The unblinding map written beside the queue it unblinds."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        items = {
            item: Pair(arm, condition, transcript, int(sample_), canary)
            for item, (arm, condition, transcript, sample_, canary) in data["items"].items()
        }
        return Key(data["round"], data["rubric_sha256"], bool(data["evidence"]), items)
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError(f"{path}: not a readable grading key ({exc})") from exc


def resolve(decisions: Mapping[str, Decision], key: Key) -> Pass:
    """Unblind one round's decisions against its key.

    A decision naming no item in the key raises: it is a typo that grades nothing,
    and the pair it was meant for would land in `ungraded` and withhold a rate with
    no sign of why. Same call `aggregate._check_grades` makes, one step earlier.

    A key item with no decision does *not* raise — a hand-graded artefact arrives
    one batch at a time, and #13 already reports the ungraded remainder.
    """
    unknown = sorted(set(decisions) - set(key.items))
    if unknown:
        raise ValueError(
            f"{len(unknown)} decision(s) name no item in the {key.round} key {unknown[:3]}"
        )
    return Pass(
        key.round,
        key.rubric_sha256,
        key.evidence,
        {key.items[item]: decision for item, decision in decisions.items()},
    )


def grades(graded: Pass) -> list[dict]:
    """The published grade file: what `aggregate.load_grades` reads.

    First round only. The re-grade measures the grader; letting it revise the
    record would measure a grader who had already been allowed a second look, and
    the agreement number would then describe nothing.

    Each entry carries the rubric's digest and the round beside the call, for the
    same reason `aggregate._provenance` repeats its stamp on every row: the grade
    file is committed and the rubric is not attached to it any other way.
    `load_grades` reads five keys and ignores the rest, so the stamp is free.
    """
    if graded.round != RECORD_ROUND:
        raise ValueError(
            f"round {graded.round!r} is not the record: only {RECORD_ROUND!r} is published, "
            "and a re-grade never revises it (grading/rubric.md, Protocol)"
        )
    current = rubric_sha256()
    if graded.rubric_sha256 != current:
        raise ValueError(
            f"these grades were taken under rubric {graded.rubric_sha256[:12]} and the file "
            f"now hashes to {current[:12]} — record the change and re-grade the affected "
            "items rather than publishing under a rubric that no longer says this"
        )
    return [
        {
            "arm": pair.arm,
            "condition": pair.condition,
            "transcript": pair.transcript,
            "sample": pair.sample,
            "canary": pair.canary,
            LOCATED: decision.located,
            "precise": decision.precise,
            "note": decision.note,
            "round": graded.round,
            "rubric_sha256": graded.rubric_sha256,
        }
        for pair, decision in sorted(graded.grades.items(), key=lambda kv: kv[0].key)
    ]


# ---------------------------------------------------------------------- agreement


@dataclass(frozen=True)
class Agreement:
    """Two passes over the same pairs, on one field.

    `kappa` is None where chance agreement is 1 — both passes constant and equal —
    because there a kappa is undefined rather than zero, and a printed 0 would read
    as "no better than chance" for a grader who agreed with himself on everything.
    """

    field: str
    n: int
    agreements: int
    kappa: float | None
    reason: str
    disagreements: tuple[Pair, ...]

    @property
    def rate(self) -> float | None:
        """Raw agreement. None, never 0.0, when nothing was graded twice."""
        return None if not self.n else self.agreements / self.n

    def row(self) -> dict:
        return {
            "field": self.field,
            "n": self.n,
            "agreements": self.agreements,
            "agreement_rate": None if self.rate is None else round(self.rate, 6),
            "cohens_kappa": None if self.kappa is None else round(self.kappa, 6),
            "reason": self.reason,
            "disagreements": [list(p.key) for p in self.disagreements],
        }


def _kappa(calls: Sequence[tuple[bool, bool]]) -> tuple[float | None, str]:
    """Cohen's kappa over paired binary calls, and why it is missing when it is.

    Reported beside the raw rate because raw agreement is inflated exactly where
    this metric is likely to sit: if 90% of claims are `false`, a grader who
    answered `false` blindly would post 90% agreement.
    """
    n = len(calls)
    if not n:
        return None, "no pair carries this field in both rounds"
    observed = sum(a == b for a, b in calls) / n
    chance = sum(
        (sum(a == v for a, _ in calls) / n) * (sum(b == v for _, b in calls) / n)
        for v in (True, False)
    )
    if chance == 1:
        return None, "both rounds gave every pair the same answer, so kappa is undefined"
    return (observed - chance) / (1 - chance), ""


def agreement(first: Pass, second: Pass, field: str = LOCATED) -> Agreement:
    """Agreement between two passes over the pairs they both graded."""
    if field not in FIELDS:
        raise ValueError(f"field {field!r} is not one of {FIELDS}")
    calls, disagreements = [], []
    for pair in sorted(set(first.grades) & set(second.grades), key=lambda p: p.key):
        a, b = getattr(first.grades[pair], field), getattr(second.grades[pair], field)
        if a is None or b is None:
            continue  # `precise` is optional; an unrecorded footnote is not a call.
        calls.append((a, b))
        if a != b:
            disagreements.append(pair)
    kappa, reason = _kappa(calls)
    return Agreement(
        field, len(calls), sum(a == b for a, b in calls), kappa, reason, tuple(disagreements)
    )


def report(first: Pass, second: Pass, *, fraction: float = SAMPLE_FRACTION) -> dict:
    """The agreement number the writeup quotes, with what it is over.

    The sample is re-derived from the first pass rather than read back from a
    file — it is a pure function of the graded set, so a stored copy is a second
    thing to keep in sync. Where the re-graded pairs and the drawn sample differ,
    that is stated rather than reported as though the sample had been completed:
    an agreement rate over a self-selected subset of a random sample is not an
    agreement rate over a random sample.
    """
    if first.rubric_sha256 != second.rubric_sha256:
        raise ValueError(
            f"the two passes ran under different rubrics ({first.rubric_sha256[:12]} vs "
            f"{second.rubric_sha256[:12]}) — their agreement measures the edit, "
            "not the grader"
        )
    drawn = set(sample(first.grades, fraction))
    regraded = set(first.grades) & set(second.grades)
    reasons = []
    if missing := sorted(p.key for p in drawn - regraded):
        reasons.append(
            f"{len(missing)} sampled pair(s) were not re-graded, so this is agreement over "
            "part of the sample rather than over the sample"
        )
    if extra := sorted(p.key for p in regraded - drawn):
        reasons.append(f"{len(extra)} re-graded pair(s) were not in the drawn sample")
    if first.evidence != second.evidence:
        reasons.append(
            "the two passes were blinded differently (evidence "
            f"{first.evidence} vs {second.evidence})"
        )
    return {
        "rubric_sha256": first.rubric_sha256,
        "evidence_shown": first.evidence,
        "sample_fraction": fraction,
        "first_round_pairs": len(first.grades),
        "sampled": len(drawn),
        "regraded": len(regraded),
        "fields": [agreement(first, second, field).row() for field in FIELDS],
        "reason": "; ".join(reasons),
    }


# --------------------------------------------------------------------------- i/o


def paths(round_: str, root: Path = GRADING) -> dict[str, Path]:
    """Where a round's three files live. One naming rule, so nothing is guessed."""
    names = ("queue", "key", "decisions")
    return {name: Path(root) / f"{name}.{round_}.json" for name in names}


def write_json(path: Path, data) -> Path:
    """`newline="\\n"`: `.gitattributes` normalises to LF, and text mode on Windows
    would otherwise write CRLF and change the digest of a committed artefact."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return path


def _corpus(runs: Path):
    """`runs/`, the transcript corpus, and the manifest — the three inputs."""
    from src.transcript import load_all  # needs a built fixture; nothing else here does

    records = RunStore(runs).read_all()
    if not records:
        raise ValueError(f"no run records under {runs}")
    canaries = load_canaries()
    return records, load_all(canaries=canaries), canaries


def _queue(args) -> int:
    records, transcripts, canaries = _corpus(args.runs)
    items, key = queue(records, transcripts, canaries, evidence=args.with_evidence)
    out = paths(RECORD_ROUND, args.out)
    print(write_json(out["queue"], [item.blind() for item in items]))
    print(write_json(out["key"], key.to_json()))
    print(f"{len(items)} item(s) to grade — do not open {out['key'].name} while grading")
    return 0


def _regrade(args) -> int:
    first = resolve(load_decisions(args.decisions), load_key(args.key))
    drawn = sample(first.grades, args.fraction)
    records, transcripts, canaries = _corpus(args.runs)
    items, key = queue(
        records,
        transcripts,
        canaries,
        round_=REGRADE_ROUND,
        only=drawn,
        # Blinded the same way as the pass it is compared against, or the two
        # passes differ in what the grader could see as well as in when.
        evidence=first.evidence,
    )
    out = paths(REGRADE_ROUND, args.out)
    print(write_json(out["queue"], [item.blind() for item in items]))
    print(write_json(out["key"], key.to_json()))
    print(f"{len(items)} of {len(first.grades)} pair(s) re-blinded for a second pass")
    return 0


def _unblind(args) -> int:
    graded = resolve(load_decisions(args.decisions), load_key(args.key))
    print(write_json(args.out, grades(graded)))
    return 0


def _agreement(args) -> int:
    first = resolve(load_decisions(args.decisions), load_key(args.key))
    second = resolve(load_decisions(args.regrade_decisions), load_key(args.regrade_key))
    print(write_json(args.out, report(first, second, fraction=args.fraction)))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.grading",
        description="Blind queue, unblinding, and agreement for T3's hand-graded half.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    first, regrade = paths(RECORD_ROUND), paths(REGRADE_ROUND)

    build = commands.add_parser("queue", help="build the blind first-pass queue")
    build.add_argument("--runs", type=Path, default=RUNS)
    build.add_argument("--out", type=Path, default=GRADING)
    build.add_argument(
        "--with-evidence",
        action="store_true",
        help="include the attacker's turn prose, which names the condition on most "
        "items; recorded in the key so the artefact says it was graded that way",
    )
    build.set_defaults(run=_queue)

    second = commands.add_parser("regrade", help="re-blind a random sample for a second pass")
    second.add_argument("--runs", type=Path, default=RUNS)
    second.add_argument("--decisions", type=Path, default=first["decisions"])
    second.add_argument("--key", type=Path, default=first["key"])
    second.add_argument("--out", type=Path, default=GRADING)
    second.add_argument("--fraction", type=float, default=SAMPLE_FRACTION)
    second.set_defaults(run=_regrade)

    publish = commands.add_parser("unblind", help="publish the first pass as the grade file")
    publish.add_argument("--decisions", type=Path, default=first["decisions"])
    publish.add_argument("--key", type=Path, default=first["key"])
    publish.add_argument("--out", type=Path, default=PUBLISHED / "t3_location_grades.json")
    publish.set_defaults(run=_unblind)

    agree = commands.add_parser("agreement", help="agreement between the two passes")
    agree.add_argument("--decisions", type=Path, default=first["decisions"])
    agree.add_argument("--key", type=Path, default=first["key"])
    agree.add_argument("--regrade-decisions", type=Path, default=regrade["decisions"])
    agree.add_argument("--regrade-key", type=Path, default=regrade["key"])
    agree.add_argument("--out", type=Path, default=PUBLISHED / "t3_agreement.json")
    agree.add_argument("--fraction", type=float, default=SAMPLE_FRACTION)
    agree.set_defaults(run=_agreement)

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except ValueError as exc:
        print(exc)
        return 1


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
