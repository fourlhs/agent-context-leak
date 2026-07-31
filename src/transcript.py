"""Session transcripts: the defender's input, and the exposure record behind every denominator.

A transcript is a JSON file under `transcripts/`. It renders to plain text that
reads like a session log, and it *declares* which canaries that text surfaces.

Two rules carry the weight.

**Declared exposure must equal derived exposure.** Both drifts are silent.
Declaring a canary the text never showed inflates #13's denominator and deflates
the rate; surfacing one without declaring it drops a real leak outside every
denominator. So the validator derives the set from the rendered text and demands
equality — never a subset in either direction.

**File content is a reference into `fixture/`, resolved at load time and anchored
by text match** — never pasted, never addressed by line number. The fixture moves
(#3 adds canaries, #32 changes spacing); a pasted copy rots silently and takes
the exposure derivation down with it.

Deterministic and API-free: `rendered` is a pure function of the transcript bytes
and the fixture bytes. No timestamps, no run ids, and no metadata — `title`,
`notes`, `axes`, and `exposes` never reach the system under test.
"""

import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from src.manifest import Canary
from src.manifest import load as load_canaries
from src.scoring import score

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixture"
TRANSCRIPTS = ROOT / "transcripts"

FORMS = ("full", "partial", "referential")
TOOLS = ("read", "bash", "edit", "grep", "glob")
DELIMITERS = ("[result]", "[/result]", "[error]", "[/error]")

# ~1500 tokens, comfortably clear of Opus 5's 512-token minimum cacheable prefix
# (#10). This is a character-count approximation; the authoritative check is a
# non-zero `cache_read_input_tokens` at the pilot gate (#14).
MIN_CHARS = 6000

_KEYS = ("schema_version", "id", "title", "axes", "notes", "exposes", "turns")
_AXES = {"centrality": ("central", "incidental"), "chattiness": ("terse", "normal", "chatty")}
_TURN_KEYS = {
    "user": ("type", "text"),
    "assistant": ("type", "text"),
    "tool": ("type", "tool", "command", "ok", "result"),
}
_REF_KEYS = ("file", "match", "before", "after", "prefix")
_WINDOW_KEYS = ("before", "after", "prefix")
_ID = re.compile(r"[a-z][a-z0-9_]*")
_CANARY_TOKEN = re.compile(r"CANARY-[0-9A-Za-z_-]+")


@dataclass(frozen=True)
class Exposure:
    canary: str
    form: str


@dataclass(frozen=True)
class Transcript:
    schema_version: int
    id: str
    title: str
    axes: dict[str, str]
    notes: str
    exposes: tuple[Exposure, ...]
    turns: tuple[dict, ...]
    # Computed at load and stored, so a later consumer (#10) cannot silently
    # re-render the same transcript against a different fixture root.
    rendered: str


# --------------------------------------------------------------------------- refs


def _ref_path(ref: dict, fixture_root: Path) -> Path:
    relative = PurePosixPath(ref["file"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"ref file {ref['file']!r} must be relative to the fixture root")
    path = (fixture_root / relative).resolve()
    if not path.is_relative_to(fixture_root.resolve()):
        raise ValueError(f"ref file {ref['file']!r} escapes {fixture_root}")
    if not path.is_file():
        raise ValueError(f"ref file {ref['file']!r} does not exist under {fixture_root}")
    return path


def _resolve_ref(ref: dict, fixture_root: Path) -> str:
    lines = _ref_path(ref, fixture_root).read_text(encoding="utf-8").rstrip("\n").split("\n")
    if "match" not in ref:
        return "\n".join(lines)
    hits = [i for i, line in enumerate(lines) if ref["match"] in line]
    if len(hits) != 1:
        raise ValueError(
            f"ref {ref['file']}: {len(hits)} lines contain {ref['match']!r}, need exactly 1"
        )
    start = max(0, hits[0] - ref.get("before", 0))
    stop = hits[0] + ref.get("after", 0) + 1
    return "\n".join(ref.get("prefix", "") + line for line in lines[start:stop])


def _resolve(block, fixture_root: Path) -> str:
    parts = block if isinstance(block, list) else [block]
    return "\n".join(p if isinstance(p, str) else _resolve_ref(p, fixture_root) for p in parts)


def _bodies(turns: Sequence[dict], fixture_root: Path) -> list[str]:
    return [_resolve(t["result"] if t["type"] == "tool" else t["text"], fixture_root) for t in turns]


def _render(turns: Sequence[dict], bodies: Sequence[str]) -> str:
    blocks = []
    for turn, body in zip(turns, bodies):
        if turn["type"] == "tool":
            tag = "result" if turn["ok"] else "error"
            blocks.append(f"[tool:{turn['tool']}] {turn['command']}\n[{tag}]\n{body}\n[/{tag}]")
        else:
            blocks.append(f"[{turn['type']}]\n{body}")
    return "\n\n".join(blocks) + "\n"


# ----------------------------------------------------------------------- exposure


def derive_exposure(rendered: str, canaries: Iterable[Canary]) -> tuple[Exposure, ...]:
    """The form each canary takes in `rendered`, by first match: full > partial > referential.

    Three levels rather than two because an agent can enable a T2 leak for a
    canary whose string it never saw — reading `config.py`, which names the env
    var, without ever reading `.env`.

    The referential test is `scoring.py`'s matcher, imported rather than forked:
    one definition means #30's change to it surfaces loudly here.
    """
    canaries = tuple(canaries)
    markers = {s.canary_id: bool(s.matched_markers) for s in score(rendered, canaries).scores}
    found = []
    for c in canaries:
        if c.context.strip("\n") in rendered:
            found.append(Exposure(c.id, "full"))
        elif c.canary_string in rendered:
            found.append(Exposure(c.id, "partial"))
        elif markers[c.id]:
            found.append(Exposure(c.id, "referential"))
    return tuple(sorted(found, key=lambda e: e.canary))


def coverage(transcripts: Iterable[Transcript], canaries: Iterable[Canary]) -> dict[str, int]:
    """How many transcripts expose each canary — #8's acceptance check."""
    counts = {c.id: 0 for c in canaries}
    for t in transcripts:
        for e in t.exposes:
            counts[e.canary] += 1
    return counts


def _known_tokens(canaries: Iterable[Canary]) -> set[str]:
    """Every CANARY token an author may legitimately have surfaced."""
    tokens: set[str] = set()
    for c in canaries:
        tokens.add(c.canary_string)
        tokens |= set(_CANARY_TOKEN.findall(c.context))
    return tokens


# ---------------------------------------------------------------------- structure


def _check_block(block, at: str) -> None:
    if not isinstance(block, (str, list)):
        raise ValueError(at + "block must be a string or a list of strings and refs")
    if isinstance(block, list) and not block:
        raise ValueError(at + "block must not be an empty list")
    for part in block if isinstance(block, list) else [block]:
        if isinstance(part, str):
            continue
        if not isinstance(part, dict) or "file" not in part:
            raise ValueError(at + f"block part {part!r} must be a string or a ref with 'file'")
        unexpected = [k for k in part if k not in _REF_KEYS]
        if unexpected:
            raise ValueError(at + f"ref has unexpected keys {unexpected}")
        orphaned = [k for k in _WINDOW_KEYS if k in part and "match" not in part]
        if orphaned:
            raise ValueError(at + f"ref keys {orphaned} are only legal alongside 'match'")
        for key in ("before", "after"):
            if not isinstance(part.get(key, 0), int) or part.get(key, 0) < 0:
                raise ValueError(at + f"ref {key} must be a non-negative integer")


def _check_turns(turns, at: str) -> None:
    if not isinstance(turns, (list, tuple)) or not turns:
        raise ValueError(at + "turns must be a non-empty list")
    kinds = []
    for i, turn in enumerate(turns):
        where = at + f"turn {i}: "
        kind = turn.get("type") if isinstance(turn, dict) else None
        if kind not in _TURN_KEYS:
            raise ValueError(where + f"type {kind!r} not in {tuple(_TURN_KEYS)}")
        if set(turn) != set(_TURN_KEYS[kind]):
            raise ValueError(where + f"keys {sorted(turn)} != {sorted(_TURN_KEYS[kind])}")
        if kind == "tool":
            if turn["tool"] not in TOOLS:
                raise ValueError(where + f"tool {turn['tool']!r} not in {TOOLS}")
            command = turn["command"]
            if not isinstance(command, str) or not command.strip() or "\n" in command:
                raise ValueError(where + "command must be a non-empty single line")
            if not isinstance(turn["ok"], bool):
                raise ValueError(where + "ok must be a boolean")
        _check_block(turn["result"] if kind == "tool" else turn["text"], where)
        kinds.append(kind)
    if kinds[0] != "user":
        raise ValueError(at + f"first turn is {kinds[0]!r}, must be user")
    if kinds[-1] != "assistant":
        raise ValueError(at + f"last turn is {kinds[-1]!r}, must be assistant")
    for kind in _TURN_KEYS:
        if kind not in kinds:
            raise ValueError(at + f"needs at least one {kind} turn")


def _check_exposes(exposes, at: str) -> None:
    if not isinstance(exposes, (list, tuple)) or not exposes:
        raise ValueError(at + "exposes must be a non-empty list")
    ids = []
    for e in exposes:
        if not isinstance(e, dict) or set(e) != {"canary", "form"}:
            raise ValueError(at + f"exposure {e!r} needs exactly 'canary' and 'form'")
        if e["form"] not in FORMS:
            raise ValueError(at + f"exposure form {e['form']!r} not in {FORMS}")
        ids.append(e["canary"])
    if ids != sorted(set(ids)):
        raise ValueError(at + "exposes must be sorted by canary and free of duplicates")


def _check_shape(data: dict, stem: str) -> None:
    missing = [k for k in _KEYS if k not in data]
    unexpected = [k for k in data if k not in _KEYS]
    if missing or unexpected:
        raise ValueError(f"{stem}: missing {missing}, unexpected {unexpected}")
    at = f"{stem}: "
    if data["schema_version"] != 1:
        raise ValueError(at + f"schema_version {data['schema_version']!r} != 1")
    if not isinstance(data["id"], str) or not _ID.fullmatch(data["id"]):
        raise ValueError(at + f"id {data['id']!r} is not ^[a-z][a-z0-9_]*$")
    if data["id"] != stem:
        raise ValueError(at + f"id {data['id']!r} does not match filename stem {stem!r}")
    if not isinstance(data["title"], str) or not 0 < len(data["title"]) <= 80:
        raise ValueError(at + "title must be a string of 1 to 80 characters")
    if not isinstance(data["notes"], str):
        raise ValueError(at + "notes must be a string")
    if not isinstance(data["axes"], dict) or set(data["axes"]) != set(_AXES):
        raise ValueError(at + f"axes keys must be exactly {sorted(_AXES)}")
    for name, allowed in _AXES.items():
        if data["axes"][name] not in allowed:
            raise ValueError(at + f"axes.{name} {data['axes'][name]!r} not in {allowed}")
    _check_turns(data["turns"], at)
    _check_exposes(data["exposes"], at)


# ---------------------------------------------------------------------- validation


def _check_equality(declared: tuple[Exposure, ...], derived: tuple[Exposure, ...], at: str) -> None:
    """Equality, not subset — the error names the canary *and* the direction of the drift."""
    want = {e.canary: e.form for e in declared}
    got = {e.canary: e.form for e in derived}
    for canary in sorted(set(want) | set(got)):
        if canary not in got:
            raise ValueError(
                at + f"{canary}: declared {want[canary]!r} but the rendered text does not "
                "surface it — this inflates the denominator and deflates the rate"
            )
        if canary not in want:
            raise ValueError(
                at + f"{canary}: rendered text surfaces it as {got[canary]!r} but it is not "
                "declared — this drops a real leak outside every denominator"
            )
        if want[canary] != got[canary]:
            raise ValueError(at + f"{canary}: declared {want[canary]!r} but surfaced {got[canary]!r}")


def _payload(t: Transcript) -> dict:
    data = {k: getattr(t, k) for k in _KEYS}
    data["exposes"] = [{"canary": e.canary, "form": e.form} for e in t.exposes]
    return data


def validate(t: Transcript, canaries: Iterable[Canary], *, fixture_root: Path = FIXTURE) -> None:
    """Raise ValueError describing the first problem found."""
    canaries = tuple(canaries)
    _check_shape(_payload(t), t.id)
    at = f"{t.id}: "

    bodies = _bodies(t.turns, fixture_root)
    for turn, body in zip(t.turns, bodies):
        clashing = [d for d in DELIMITERS if d in body]
        if clashing:
            raise ValueError(at + f"{turn['type']} content contains render delimiters {clashing}")
    if _render(t.turns, bodies) != t.rendered:
        raise ValueError(at + f"stored render does not match the fixture at {fixture_root}")

    if "\r" in t.rendered:
        raise ValueError(at + "rendered text contains a carriage return")
    if len(t.rendered) < MIN_CHARS:
        raise ValueError(at + f"rendered text is {len(t.rendered)} chars, minimum {MIN_CHARS}")

    # A hand-typed near-miss would corrupt exposure derivation here and pollute
    # #13's near-miss metric downstream, so it is rejected rather than counted.
    unknown = sorted(set(_CANARY_TOKEN.findall(t.rendered)) - _known_tokens(canaries))
    if unknown:
        raise ValueError(at + f"rendered text has unknown CANARY tokens {unknown}")

    strangers = sorted({e.canary for e in t.exposes} - {c.id for c in canaries})
    if strangers:
        raise ValueError(at + f"exposes unknown canary ids {strangers}")
    _check_equality(t.exposes, derive_exposure(t.rendered, canaries), at)


# --------------------------------------------------------------------------- load


def _build(path: Path, fixture_root: Path) -> Transcript:
    data = json.loads(path.read_text(encoding="utf-8"))
    _check_shape(data, path.stem)
    turns = tuple(data["turns"])
    return Transcript(
        schema_version=data["schema_version"],
        id=data["id"],
        title=data["title"],
        axes=dict(data["axes"]),
        notes=data["notes"],
        exposes=tuple(Exposure(e["canary"], e["form"]) for e in data["exposes"]),
        turns=turns,
        rendered=_render(turns, _bodies(turns, fixture_root)),
    )


def load(
    path, *, fixture_root: Path = FIXTURE, canaries: Iterable[Canary] | None = None
) -> Transcript:
    """Read one transcript, render it against `fixture_root`, and validate it."""
    transcript = _build(Path(path), fixture_root)
    validate(transcript, load_canaries() if canaries is None else canaries, fixture_root=fixture_root)
    return transcript


def load_all(
    directory=TRANSCRIPTS,
    *,
    fixture_root: Path = FIXTURE,
    canaries: Iterable[Canary] | None = None,
) -> tuple[Transcript, ...]:
    """Every transcript in `directory`, sorted by id."""
    canaries = load_canaries() if canaries is None else tuple(canaries)
    loaded = tuple(
        sorted(
            (load(p, fixture_root=fixture_root, canaries=canaries)
             for p in Path(directory).glob("*.json")),
            key=lambda t: t.id,
        )
    )
    ids = [t.id for t in loaded]
    if len(set(ids)) != len(ids):
        raise ValueError(f"duplicate transcript ids: {sorted(ids)}")
    return loaded


# ---------------------------------------------------------------------------- cli


def main(argv: list[str]) -> int:
    command, *rest = argv or ["check"]
    canaries = load_canaries()
    if command == "check":
        for t in load_all(canaries=canaries):
            forms = ", ".join(f"{e.canary}={e.form}" for e in t.exposes)
            print(f"ok {t.id}  {len(t.rendered)} chars  {len(t.turns)} turns  [{forms}]")
        return 0
    if command in ("render", "exposure") and rest:
        # `_build`, not `load`: both subcommands exist to inspect a transcript
        # whose declared `exposes` is still wrong, which `load` would reject.
        t = _build(TRANSCRIPTS / f"{rest[0]}.json", FIXTURE)
        if command == "render":
            sys.stdout.write(t.rendered)
        else:
            derived = [{"canary": e.canary, "form": e.form}
                       for e in derive_exposure(t.rendered, canaries)]
            print(json.dumps(derived, indent=2))
        return 0
    print("usage: python -m src.transcript check | render <id> | exposure <id>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
