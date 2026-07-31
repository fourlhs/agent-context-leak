"""Run records — one JSON per (stage, condition, transcript, sample).

Every model-calling stage writes a record here before anything else reads it,
so scoring, re-scoring, and the cost summariser never re-call the API.
`exists()` is the resume gate: the caller checks it before making a request, so
an interrupted run resumes instead of paying twice for calls that completed.

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
gate (#14) exists to catch.
"""

import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

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


def _slug(value: str) -> str:
    """One path component. Each field gets its own directory level, so two
    fields can never merge into an ambiguous filename."""
    return _UNSAFE.sub("-", value) or _EMPTY


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
        return self.path_for(stage, condition, transcript, sample).exists()

    def write(self, record: RunRecord) -> Path:
        path = self.path_for(
            record.stage, record.condition, record.transcript, record.sample
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        # Unique per process, and not `*.json`, so a crashed writer's leftovers
        # are invisible to `read_all` and cannot collide with another writer's.
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp.write_text(
            json.dumps(asdict(record), indent=2, sort_keys=True), encoding="utf-8"
        )
        os.replace(tmp, path)  # atomic on POSIX and on Windows
        return path

    def read_all(self) -> tuple[RunRecord, ...]:
        return tuple(_read(p) for p in sorted(self.root.rglob("*.json")))


def git_sha(repo: Path = RUNS.parent) -> str:
    """The commit to stamp onto records. Callers pass the result to `write()`;
    `write()` never calls this itself — see the module docstring."""
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
