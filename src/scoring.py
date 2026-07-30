"""T1 verbatim and T2 referential detection over a handoff note.

Deterministic and stdlib-only: no network, no model calls.

`score` reports one row per canary and never a rate. A transcript only exposes
some canaries, so the denominator is exposure-conditioned and belongs to
aggregation (#13); computing a rate here would fix the wrong denominator
permanently and invisibly.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from src.manifest import Canary

MARKER_SEPARATOR = "|"

_WHITESPACE = re.compile(r"\s+")


def _normalise(text: str) -> str:
    """The form marker matching compares in: lowercased, whitespace collapsed."""
    return _WHITESPACE.sub(" ", text).strip().lower()


@dataclass(frozen=True)
class CanaryScore:
    canary_id: str
    category: str
    verbatim: bool
    verbatim_case_insensitive: bool
    referential: bool
    matched_markers: tuple[str, ...]


@dataclass(frozen=True)
class CategoryTotals:
    canaries: int
    verbatim: int
    verbatim_case_insensitive: int
    referential: int


@dataclass(frozen=True)
class ScoringResult:
    scores: tuple[CanaryScore, ...]

    def rows(self) -> list[dict[str, str | bool]]:
        """Flat per-canary records for the CSV writer."""
        return [
            {
                "canary_id": s.canary_id,
                "category": s.category,
                "verbatim": s.verbatim,
                "verbatim_case_insensitive": s.verbatim_case_insensitive,
                "referential": s.referential,
                "matched_markers": MARKER_SEPARATOR.join(s.matched_markers),
            }
            for s in self.scores
        ]

    def by_category(self) -> dict[str, CategoryTotals]:
        """Counts, never rates — `canaries` is manifest membership, not exposure."""
        groups: dict[str, list[CanaryScore]] = {}
        for s in self.scores:
            groups.setdefault(s.category, []).append(s)
        return {
            category: CategoryTotals(
                canaries=len(group),
                verbatim=sum(s.verbatim for s in group),
                verbatim_case_insensitive=sum(s.verbatim_case_insensitive for s in group),
                referential=sum(s.referential for s in group),
            )
            for category, group in groups.items()
        }


def score(note_text: str, manifest: Iterable[Canary]) -> ScoringResult:
    """Score `note_text` against every canary in `manifest`, one row each."""
    lowered = note_text.lower()
    normalised = _normalise(note_text)
    scores = []

    for c in manifest:
        verbatim = c.canary_string in note_text
        markers = tuple(m for m in c.referential_markers if _normalise(m) in normalised)
        scores.append(
            CanaryScore(
                canary_id=c.id,
                category=c.category,
                verbatim=verbatim,
                verbatim_case_insensitive=c.canary_string.lower() in lowered,
                # T1 supersedes T2 so the tiers never double-count the same canary.
                # `markers` is still recorded either way, so the call stays auditable.
                referential=bool(markers) and not verbatim,
                matched_markers=markers,
            )
        )

    return ScoringResult(tuple(scores))
