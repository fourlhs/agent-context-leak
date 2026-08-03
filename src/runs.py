"""Run records — one JSON per (stage, condition, transcript, sample).

Every model-calling stage writes a record here before anything else reads it,
so scoring, re-scoring, and the cost summariser never re-call the API. C3 keeps
its pre-scrub generation in `raw_output`, so re-tuning the scrubber re-scores
off disk instead of re-calling the defender 90 times.

`exists()` is the resume gate: the caller checks it before making a request, so
an interrupted run resumes instead of paying twice for calls that completed.
**It keys on the four coordinates only** — a record written under a different
prompt, model, or effort still counts as done. That is correct for a resumed
run and wrong for a relaunched one, so a driver that changed any of those
compares against `read()` instead, and `runs_report` warns when one stage ends
up holding more than one setting.

All four usage fields are recorded even when a provider returns zero.
`cache_read_input_tokens` is the only signal that #10's prompt-caching layout is
working — a persistent zero means something volatile got into the cached prefix
and the defender bill is roughly double what it should be.

`created_at` and `git_sha` are supplied by the caller, never read from the clock
or from git inside `write()`: a value read at write time cannot be reproduced
later, and tests must be deterministic. `git_sha()` is here for the caller's
convenience and is never called implicitly.

Writes are atomic — temp file, then rename — so a process killed mid-write
leaves either nothing or a whole record. If a malformed record does turn up,
`read_all()` raises naming the file rather than skipping it: a silently dropped
record under-reports spend, and under-reporting is the exact failure the pilot
gate (#14) exists to catch. `read_readable()` is the deliberate exception, for
the one caller that must still produce a floor when a record is unreadable.
"""

import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import uuid4

RUNS = Path(__file__).resolve().parents[1] / "runs"

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
# Stands in for a path component that is empty — `condition` is "" on stages
# that have none, and a bare "" is not a directory name.
_EMPTY = "_"


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int
    cache_read_input_tokens: int
    cache_creation_input_tokens: int


@dataclass(frozen=True)
class RunRecord:
    stage: str  # "defender" | "attacker" | "control"
    condition: str  # "C1" | "C2" | "C3", or "" where not applicable
    transcript: str
    sample: int
    output: str
    model: str
    effort: str
    prompt_hash: str
    usage: Usage
    git_sha: str
    created_at: str  # ISO 8601, supplied by the caller
    # Why the stage stopped. Computed at every call site and, before #14, thrown
    # away: a defender refusal then left no trace anywhere, because the record it
    # would have appeared on was never written. Defaulted, so records written
    # before it existed still load. The attacker's per-turn reasons stay in
    # `raw_output`; this is the one that ended the stage.
    stop_reason: str = ""
    # C3's pre-scrub generation; "" wherever there is nothing else to keep.
    # `output` is always the text that leaves the stage — what the attacker
    # sees — so #11 is unaffected by this field existing. Defaulted, so records
    # written before it existed still load and the other stages ignore it.
    raw_output: str = ""


def _slug(value: str) -> str:
    """One path component. Each field gets its own directory level, so two
    fields can never merge into an ambiguous filename."""
    slug = _UNSAFE.sub("-", value)
    # "", "." and ".." are not usable component names. Stripping dots rather
    # than listing the two cases keeps the invariant the tests assert true by
    # construction rather than by enumeration.
    return slug if slug.strip(".") else _EMPTY


def _read(path: Path) -> RunRecord:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return RunRecord(usage=Usage(**data.pop("usage")), **data)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValueError(f"{path}: not a readable run record ({exc})") from exc


class RunStore:
    def __init__(self, root: Path = RUNS) -> None:
        self.root = Path(root)

    def path_for(self, stage: str, condition: str, transcript: str, sample: int) -> Path:
        return (
            self.root
            / _slug(stage)
            / _slug(condition)
            / _slug(transcript)
            / f"{sample:03d}.json"
        )

    def exists(self, stage: str, condition: str, transcript: str, sample: int) -> bool:
        """The resume gate. Keys on the four coordinates only — see the module
        docstring on why a relaunch under new provenance needs `read()`."""
        return self.path_for(stage, condition, transcript, sample).exists()

    def read(
        self, stage: str, condition: str, transcript: str, sample: int
    ) -> RunRecord | None:
        """The record for this key, or None. A driver whose prompt, model, or
        effort has changed compares against this and re-calls, instead of
        trusting `exists()` and keeping a record from the old settings."""
        path = self.path_for(stage, condition, transcript, sample)
        return _read(path) if path.exists() else None

    def write(self, record: RunRecord) -> Path:
        path = self.path_for(
            record.stage, record.condition, record.transcript, record.sample
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        # Sweep this key's leftovers from earlier crashed writes. Scoped to the
        # key, and done before our own temp exists, so a concurrent writer of
        # another sample is never touched.
        for stale in path.parent.glob(f"{path.name}.*.tmp"):
            stale.unlink(missing_ok=True)
        # Not `*.json`, so a crash leaves nothing `read_all` can see; uuid
        # rather than pid, so two writers in one process cannot collide either.
        tmp = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        tmp.write_text(
            json.dumps(asdict(record), indent=2, sort_keys=True), encoding="utf-8"
        )
        os.replace(tmp, path)  # atomic on POSIX and on Windows
        return path

    def read_all(self) -> tuple[RunRecord, ...]:
        """Every record, or a ValueError naming the first unreadable one."""
        return tuple(_read(p) for p in sorted(self.root.rglob("*.json")))

    def read_readable(self) -> tuple[tuple[RunRecord, ...], tuple[Path, ...]]:
        """Every record that loads, and the paths that did not. For the
        summariser only: a malformed record must not cost the operator the
        number, but it must never be dropped quietly either, so the caller is
        handed both halves and has to say which it is reporting."""
        records, unreadable = [], []
        for path in sorted(self.root.rglob("*.json")):
            try:
                records.append(_read(path))
            except ValueError:
                unreadable.append(path)
        return tuple(records), tuple(unreadable)


def git_sha(repo: Path = RUNS.parent) -> str:
    """The commit to stamp onto records. Callers pass the result to `write()`;
    `write()` never calls this itself — see the module docstring."""
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
