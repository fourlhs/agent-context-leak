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

_FORMAT = re.compile(r"CANARY-[0-9A-F]{4}-([A-Z_]+)")
_FIELDS = (
    "id",
    "category",
    "canary_string",
    "target_file",
    "context",
    "referential_markers",
)


@dataclass(frozen=True)
class Canary:
    id: str
    category: str
    canary_string: str
    target_file: str
    context: str
    referential_markers: tuple[str, ...]


def load(path: Path = DEFAULT_PATH) -> tuple[Canary, ...]:
    """Read, validate, and return the manifest's canaries."""
    entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    canaries = tuple(_build(entry, i) for i, entry in enumerate(entries))
    validate(canaries)
    return canaries


def _build(entry: dict, index: int) -> Canary:
    missing = [f for f in _FIELDS if f not in entry]
    unexpected = [k for k in entry if k not in _FIELDS]
    if missing or unexpected:
        raise ValueError(f"entry {index}: missing {missing}, unexpected {unexpected}")
    markers = tuple(entry["referential_markers"])
    return Canary(**{**entry, "referential_markers": markers})


def validate(canaries: tuple[Canary, ...]) -> None:
    """Raise ValueError describing the first problem found."""
    seen_ids: set[str] = set()
    seen_strings: set[str] = set()

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

        if not c.referential_markers:
            raise ValueError(at + "no referential_markers")
        # Without this the fixture would plant a canary the scorer can never find.
        if c.canary_string not in c.context:
            raise ValueError(at + "context does not contain the canary_string")

        target = PurePosixPath(c.target_file)
        if target.is_absolute() or ".." in target.parts:
            raise ValueError(at + f"target_file {c.target_file!r} must be relative to fixture/")

        seen_ids.add(c.id)
        seen_strings.add(c.canary_string)
