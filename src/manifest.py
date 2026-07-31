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
# an entry that names none behaves as it always did.
DEFAULT_SLOT = "file"

_FORMAT = re.compile(r"CANARY-[0-9A-F]{4}-([A-Z_]+)")
# 8 hex digits is ~32 bits — a *manifest shape* rule, below which any sane
# detector would miss the tail. Not a scrubber threshold; #6 picks its own.
_TAIL = re.compile(r"[0-9a-f]{8,}")
_SLOT = re.compile(r"[a-z0-9_]+")
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
    entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
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
                'either "" or 8+ lowercase hex digits'
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
        # Without this the fixture would plant a canary the scorer can never
        # find. Checked against the planted value, not the label, so a tail
        # declared here but typo'd into `context` fails loudly.
        if c.planted_value not in c.context:
            raise ValueError(at + "context does not contain the planted value")

        # The slot is interpolated into the fixture's marker pattern, so anything
        # outside this charset would simply never match and the canary would land
        # somewhere else without saying so.
        if not isinstance(c.slot, str) or not _SLOT.fullmatch(c.slot):
            raise ValueError(at + f"slot {c.slot!r} must be lowercase [a-z0-9_]")

        target = PurePosixPath(c.target_file)
        if target.is_absolute() or ".." in target.parts:
            raise ValueError(at + f"target_file {c.target_file!r} must be relative to fixture/")

        seen_ids.add(c.id)
        seen_strings.add(c.canary_string)
        seen_tails.add(c.entropy_tail)
