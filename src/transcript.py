"""Load and validate session transcripts — the defender's input.

A transcript is a recorded working session against `fixture/`: what the operator
asked, what the agent said, and every file the agent actually opened. `render`
flattens one back into the plain-text session log the defender is asked to
distil, and is the single definition of that text — scoring, exposure checking,
and the defender must all agree on it or they are measuring different documents.

The load-bearing field is `exposes`.

A transcript surfaces only some canaries. Per-category rates in #13 are
conditioned on that exposure: the denominator counts (canary, sample) pairs where
the canary was actually in front of the agent. A canary the agent never saw
cannot be leaked, and counting it as a clean miss silently deflates its category.

So `exposes` is **verified, not trusted**. `validate` renders the transcript and
compares the declared set against the canaries whose strings actually appear in
that text. Declaring one that is absent fails; surfacing one you did not declare
fails too. The second direction is the one that matters — an undeclared canary is
a leak the aggregation would never know to count.
"""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from src.manifest import Canary

DEFAULT_DIR = Path(__file__).resolve().parents[1] / "transcripts"

ROLES = ("user", "assistant", "tool_call", "tool_result")

_TURN_FIELDS = ("role", "text", "tool", "file")
_FIELDS = ("id", "summary", "exposes", "turns")


@dataclass(frozen=True)
class Turn:
    role: str
    text: str
    tool: str | None = None
    # Set on a tool_result that quotes a fixture file, so tests can assert the
    # quote is faithful. A transcript quoting a file that has since changed is a
    # broken transcript, not a stale test.
    file: str | None = None


@dataclass(frozen=True)
class Transcript:
    id: str
    summary: str
    exposes: tuple[str, ...]
    turns: tuple[Turn, ...]

    def render(self) -> str:
        """The session log exactly as the defender receives it."""
        return "\n\n".join(_render_turn(t) for t in self.turns) + "\n"


def _render_turn(turn: Turn) -> str:
    if turn.role == "tool_call":
        return f"[{turn.tool}] {turn.text}"
    if turn.role == "tool_result":
        return f"[{turn.tool} → result]\n{turn.text}"
    return f"[{turn.role}]\n{turn.text}"


def load(path: Path, manifest: Iterable[Canary]) -> Transcript:
    """Read, validate, and return one transcript."""
    transcript = _build(json.loads(path.read_text(encoding="utf-8")))
    if transcript.id != path.stem:
        raise ValueError(f"{path.name}: id {transcript.id!r} does not match filename")
    validate(transcript, manifest)
    return transcript


def load_all(manifest: Iterable[Canary], directory: Path = DEFAULT_DIR) -> tuple[Transcript, ...]:
    canaries = tuple(manifest)
    transcripts = tuple(load(p, canaries) for p in sorted(directory.glob("*.json")))
    ids = [t.id for t in transcripts]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate transcript id")
    return transcripts


def _build(raw: dict) -> Transcript:
    missing = [f for f in _FIELDS if f not in raw]
    unexpected = [k for k in raw if k not in _FIELDS]
    if missing or unexpected:
        raise ValueError(f"transcript: missing {missing}, unexpected {unexpected}")
    return Transcript(
        id=raw["id"],
        summary=raw["summary"],
        exposes=tuple(raw["exposes"]),
        turns=tuple(_turn(t, i) for i, t in enumerate(raw["turns"])),
    )


def _turn(raw: dict, index: int) -> Turn:
    unexpected = [k for k in raw if k not in _TURN_FIELDS]
    if unexpected or "role" not in raw or "text" not in raw:
        raise ValueError(f"turn {index}: bad fields {sorted(raw)}")
    return Turn(**raw)


def validate(transcript: Transcript, manifest: Iterable[Canary]) -> None:
    """Raise ValueError describing the first problem found."""
    canaries = tuple(manifest)
    at = f"{transcript.id}: "

    if not transcript.summary.strip():
        raise ValueError(at + "empty summary")
    if not transcript.turns:
        raise ValueError(at + "no turns")
    if transcript.turns[0].role != "user":
        raise ValueError(at + "first turn must be user")

    _validate_turns(transcript, at)
    _validate_exposure(transcript, canaries, at)


def _validate_turns(transcript: Transcript, at: str) -> None:
    pending: str | None = None
    for i, turn in enumerate(transcript.turns):
        where = at + f"turn {i}: "
        if turn.role not in ROLES:
            raise ValueError(where + f"unknown role {turn.role!r}")
        if not turn.text.strip():
            raise ValueError(where + "empty text")

        if turn.role == "tool_call":
            if not turn.tool:
                raise ValueError(where + "tool_call needs a tool")
            pending = turn.tool
        elif turn.role == "tool_result":
            # An unpaired result is a transcript that could not have happened.
            if pending is None or turn.tool != pending:
                raise ValueError(where + f"tool_result {turn.tool!r} has no matching call")
            pending = None
        elif turn.tool or turn.file:
            raise ValueError(where + f"{turn.role} cannot carry tool/file")

    if pending is not None:
        raise ValueError(at + f"tool_call {pending!r} has no result")


def _validate_exposure(transcript: Transcript, canaries: tuple[Canary, ...], at: str) -> None:
    known = {c.id for c in canaries}
    declared = set(transcript.exposes)

    if len(declared) != len(transcript.exposes):
        raise ValueError(at + "duplicate id in exposes")
    if unknown := declared - known:
        raise ValueError(at + f"exposes unknown canary {sorted(unknown)}")

    text = transcript.render()
    present = {c.id for c in canaries if c.canary_string in text}

    if missing := declared - present:
        raise ValueError(at + f"declares {sorted(missing)} but the text never surfaces it")
    if undeclared := present - declared:
        raise ValueError(at + f"surfaces {sorted(undeclared)} without declaring it")
