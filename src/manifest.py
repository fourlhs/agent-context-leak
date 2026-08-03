"""Load and validate the canary manifest.

`canaries/manifest.yaml` is the single source of truth for what gets planted in
the fixture and what counts as a leak. Nothing else may define a canary.
"""

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

CATEGORIES = (
    "env_secret",
    "hardcoded_credential",
    "customer_name_in_fixture",
    "internal_url",
    "absolute_path_with_username",
    "indiscreet_comment",
)

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "canaries" / "manifest.yaml"

# Categories whose value is secret-shaped, so C3's entropy detector needs a real
# target. A floor, not a ceiling — #3 may give other categories tails too.
TAIL_REQUIRED_CATEGORIES = ("env_secret", "hardcoded_credential")

# Where in the target file a canary lands. Every base file declares this slot, so
# an entry that names none behaves as it always did. SLOT_PATTERN is shared with
# the fixture generator, which interpolates it into its marker regex.
DEFAULT_SLOT = "file"
SLOT_PATTERN = r"[a-z0-9_]+"

# How `scoring.rows()` joins the markers that fired into one CSV cell. Defined
# here, where a marker containing it is refused, and imported there — one
# literal, so the writer and the rule cannot drift apart.
MARKER_SEPARATOR = "|"

_FORMAT = re.compile(r"CANARY-[0-9A-F]{4}-([A-Z_]+)")
# 8 hex digits is ~32 bits — a *manifest shape* rule, below which any sane
# detector would miss the tail. Not a scrubber threshold; #6 picks its own.
#
# The ceiling is a safety rule, not a shape one (#51). `transcript_guard` builds
# its whitelist from this file, so whatever validates here becomes invisible to
# the guard in every file it checks. Lowercase hex is the native encoding of a
# large class of real credentials, and 32, 40 and 64 hex characters — an HMAC
# secret, a git SHA, a 256-bit key — are the common ones. Refusing them costs
# nothing: every canary in the manifest uses a 16-character tail. It does not
# make the whitelist safe, because a 16-hex real secret still validates; see the
# module docstring in `src/transcript_guard.py` for what the whitelist does and
# does not close.
_TAIL = re.compile(r"[0-9a-f]{8,20}")
_SLOT = re.compile(SLOT_PATTERN)
# A marker's own first and last character, checked against the same class
# `scoring._BOUNDARY` asserts around it. Applied to the reversed string for the
# tail end, so one pattern covers both edges.
_MARKER_EDGE = re.compile(r"\w")
_FIELDS = (
    "id",
    "category",
    "canary_string",
    "entropy_tail",
    "target_file",
    "context",
    "referential_markers",
)
# Optional, so #3 does not have to write ten entries twice.
_OPTIONAL_FIELDS = ("slot",)


@dataclass(frozen=True)
class Canary:
    id: str
    category: str
    canary_string: str
    entropy_tail: str
    target_file: str
    context: str
    referential_markers: tuple[str, ...]
    slot: str = DEFAULT_SLOT

    @property
    def planted_value(self) -> str:
        """What the fixture actually holds, and the T1 needle.

        A property rather than a stored field so it cannot drift out of sync
        with its two parts, and so `dataclasses.replace` keeps working.

        Raises rather than degrades on a bad tail: falling back to the label
        would silently reinstate the #29 bug for any construction site that
        bypasses `validate()`, which is the failure mode this field exists to
        remove.
        """
        if not isinstance(self.entropy_tail, str):
            raise TypeError(
                f"{self.id}: entropy_tail must be a str, "
                f"got {type(self.entropy_tail).__name__}"
            )
        if not self.entropy_tail:
            return self.canary_string
        return f"{self.canary_string}-{self.entropy_tail}"


def load(path: Path = DEFAULT_PATH) -> tuple[Canary, ...]:
    """Read, validate, and return the manifest's canaries."""
    return loads(path.read_text(encoding="utf-8"))


def loads(text: str) -> tuple[Canary, ...]:
    """The same, from text already in hand.

    Split out for `transcript_guard`, which reads the manifest out of the git
    index rather than off disk (#51) and so never has a path to hand it.
    """
    entries = yaml.safe_load(text) or []
    canaries = tuple(_build(entry, i) for i, entry in enumerate(entries))
    validate(canaries)
    return canaries


def _build(entry: dict, index: int) -> Canary:
    missing = [f for f in _FIELDS if f not in entry]
    unexpected = [k for k in entry if k not in _FIELDS + _OPTIONAL_FIELDS]
    if missing or unexpected:
        raise ValueError(f"entry {index}: missing {missing}, unexpected {unexpected}")
    markers = tuple(entry["referential_markers"])
    return Canary(**{**entry, "referential_markers": markers})


def validate(canaries: tuple[Canary, ...]) -> None:
    """Raise ValueError describing the first problem found."""
    seen_ids: set[str] = set()
    seen_strings: set[str] = set()
    seen_tails: set[str] = set()
    seen_places: set[tuple[str, str]] = set()

    for c in canaries:
        at = f"{c.id}: "
        if c.id in seen_ids:
            raise ValueError(at + "duplicate id")
        if c.canary_string in seen_strings:
            raise ValueError(at + f"duplicate canary_string {c.canary_string}")
        if c.category not in CATEGORIES:
            raise ValueError(at + f"unknown category {c.category!r}")

        match = _FORMAT.fullmatch(c.canary_string)
        if not match:
            raise ValueError(at + f"{c.canary_string!r} is not CANARY-<4 hex>-<CATEGORY>")
        if match.group(1) != c.category.upper():
            raise ValueError(at + f"suffix {match.group(1)!r} != category {c.category!r}")

        # Must precede any use of planted_value, which raises TypeError on a
        # non-str tail — a bare `entropy_tail:` would otherwise surface as that
        # rather than as this ValueError.
        if not isinstance(c.entropy_tail, str) or not (
            c.entropy_tail == "" or _TAIL.fullmatch(c.entropy_tail)
        ):
            raise ValueError(
                at + f"entropy_tail {c.entropy_tail!r} must be a quoted string, "
                'either "" or 8 to 20 lowercase hex digits. The ceiling keeps the '
                "commonest real-credential hex lengths (32, 40, 64) out of the guard's "
                "whitelist — invent a 16-digit tail rather than widening it"
            )
        if c.category in TAIL_REQUIRED_CATEGORIES and not c.entropy_tail:
            raise ValueError(
                at + f"category {c.category!r} is secret-shaped, so C3 needs a real "
                "entropy target: entropy_tail may not be empty"
            )
        # The tail is a needle in its own right, so a shared one would let a
        # leak of this canary score against another.
        if c.entropy_tail and c.entropy_tail in seen_tails:
            raise ValueError(at + f"duplicate entropy_tail {c.entropy_tail}")

        if not c.referential_markers:
            raise ValueError(at + "no referential_markers")
        for marker in c.referential_markers:
            # A blank marker normalises to "", which the whole-token matcher
            # fires on wherever a non-word character sits — so the canary scores
            # T2 on an arbitrary subset of notes decided by their punctuation.
            # Worse than the substring era's "matches everything": that at least
            # showed up as an implausible 100%.
            if not isinstance(marker, str) or not marker.strip():
                raise ValueError(
                    at + f"referential_marker {marker!r} must be a non-blank string: "
                    "a blank one scores T2 on an arbitrary subset of notes"
                )
            if MARKER_SEPARATOR in marker:
                raise ValueError(
                    at + f"referential_marker {marker!r} contains the marker separator "
                    f"{MARKER_SEPARATOR!r}, so results/ would read it as two markers"
                )
            # T2 asserts a word boundary at each end of the marker (#30), so a
            # marker whose own edge is punctuation is constrained at a juncture
            # that is not one: `PAYMENTS_API_KEY=` never fires on
            # `PAYMENTS_API_KEY=xxx`, the shape it was written to catch. Refused
            # at authoring time because the symptom is a silently-zero T2 rate
            # for one category, which is invisible in the CSV.
            if not _MARKER_EDGE.match(marker) or not _MARKER_EDGE.match(marker[::-1]):
                raise ValueError(
                    at + f"referential_marker {marker!r} starts or ends with a non-word "
                    "character; T2 matches a marker as a whole token, so an edge like "
                    "that asserts a boundary where there is none and the marker can "
                    "never fire — write the bare identifier or phrase"
                )
        # Without this the fixture would plant a canary the scorer can never
        # find. Checked against the planted value, not the label, so a tail
        # declared here but typo'd into `context` fails loudly.
        if c.planted_value not in c.context:
            raise ValueError(at + "context does not contain the planted value")

        # The slot is interpolated into the fixture's marker pattern, so anything
        # outside this charset would simply never match and the canary would land
        # somewhere else without saying so.
        if not isinstance(c.slot, str) or not _SLOT.fullmatch(c.slot):
            raise ValueError(
                at + f"slot {c.slot!r} must match {SLOT_PATTERN} — the fixture's "
                "marker pattern would never find it"
            )
        # Two canaries at one slot land consecutively, which is the list of
        # secrets bolted to the top of a file that #32 removed. The generator
        # still renders it; the manifest is where it gets refused, because
        # `slot` defaulting means stacking is what you get by not thinking.
        if (c.target_file, c.slot) in seen_places:
            raise ValueError(
                at + f"another canary already fills slot {c.slot!r} in "
                f"{c.target_file}; two there read as a planted list — give one of "
                "them a different slot (scripts/build_fixture.py lists them)"
            )

        target = PurePosixPath(c.target_file)
        if target.is_absolute() or ".." in target.parts:
            raise ValueError(at + f"target_file {c.target_file!r} must be relative to fixture/")

        seen_ids.add(c.id)
        seen_strings.add(c.canary_string)
        seen_tails.add(c.entropy_tail)
        seen_places.add((c.target_file, c.slot))
