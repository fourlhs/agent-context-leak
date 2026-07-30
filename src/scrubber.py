"""C3: redact secret-shaped text from a handoff note before the note is written.

This module is deliberately **manifest-blind**. It has never seen a canary and is
not tuned to one: it keys off the generic shapes secrets take, exactly as a
production scrubber would. A scrubber that grepped for our own canaries would
score a perfect defence and tell us nothing about a real one.

Four rules, applied in this order (earlier rules win any overlap):

1. `vendor_prefix`   — vendor-recognizable key prefixes (`sk_live_`, `AKIA`, ...)
2. `url_credentials` — `user:pass@host` inside a URL; the host is kept
3. `assignment`      — the value assigned to a secret-*named* key
4. `entropy`         — standalone tokens whose shape says "random"

Two limitations, both deliberate and both belonging in the writeup:

*Prefix path is never exercised.* Our canaries carry no vendor-recognizable
prefixes (guardrail 1), so rule 1 cannot fire on this benchmark's corpus. C3 will
therefore read weaker here than an equivalent production scrubber. That is a
stated limitation, not a bug to fix by weakening the guardrail.

*Recall is preferred over precision on high-entropy hex.* A 40-character hex git
SHA is indistinguishable by shape from a 160-bit hex secret, and rule 4 redacts
it. See `test_full_git_sha_is_an_accepted_false_positive`.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass

REDACTION = "[REDACTED]"

# Length below which a token cannot carry enough material to look random.
_MIN_TOKEN = 16

# Shannon entropy is bounded by log2(length), so these floors are only reachable
# by tokens long enough to reach them: 3.0 needs 8+ chars, 4.5 needs 23+.
_HEX_ENTROPY = 3.0
_MIXED_ENTROPY = 3.5
_BLOB_ENTROPY = 4.5
_BLOB_LENGTH = 32

_HEX = re.compile(r"[0-9a-fA-F]+")

# `=` is excluded so a token can never span `KEY=value` and swallow the key name.
# Key names are referential markers; removing them is T2's job, not C3's.
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{%d,}={0,2}" % _MIN_TOKEN)

_VENDOR_PREFIX = re.compile(
    r"\b(?:sk_live_|sk_test_|pk_live_|rk_live_|AKIA|ASIA|ghp_|gho_|ghs_|github_pat_"
    r"|xox[baprs]-|AIza|ya29\.|glpat-|npm_|dop_v1_)[A-Za-z0-9_\-]{8,}"
)

# Keeps the host: `postgres://[REDACTED]@db.internal/main` still tells the next
# session which database it was, which is the whole point of a handoff note.
_URL_CREDENTIALS = re.compile(r"(?<=://)[^\s/:@]+:[^\s/@]+(?=@)")

_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)
        \s*[:=]\s*
        (?P<value>"[^"\n]*"|'[^'\n]*'|[^\s,;'")}\]]+)
    """,
    re.VERBOSE,
)

# A key whose *name* makes its value a secret regardless of what the value looks
# like — `password=hunter2` is low-entropy and still a credential.
_SECRET_KEY = re.compile(
    r"secret|token|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|credential|auth|session[_-]?id|bearer",
    re.IGNORECASE,
)

# Framework conventions that mean "this is shipped to the browser". Redacting one
# is a false positive by definition.
_PUBLIC_KEY = re.compile(r"^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_)", re.IGNORECASE)

# A dotted identifier path — `process.env.SESSION_TOKEN`, `settings.API_KEY`. This
# names where a secret is read from; it is not the secret. If such a value ever is
# one, rule 4 still sees it independently.
_REFERENCE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")

_PLACEHOLDER = re.compile(
    r"""^(?:""|''|<[^>]*>|x+|\*+|\.{2,}|-+|_+|\?+
        |null|none|nil|true|false|todo|tbd|changeme|redacted|\[REDACTED\]
        |\d+)$""",
    re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True)
class Redaction:
    """One removal. `text` is the *removed secret* — never write it to a note."""

    rule: str
    text: str
    start: int
    end: int


@dataclass(frozen=True)
class ScrubResult:
    text: str
    redactions: tuple[Redaction, ...]

    @property
    def clean(self) -> bool:
        return not self.redactions


def scrub(note: str) -> ScrubResult:
    """Return `note` with secret-shaped spans replaced by `REDACTION`."""
    spans = [
        span
        for rule, find in (
            ("vendor_prefix", _vendor_spans),
            ("url_credentials", _url_spans),
            ("assignment", _assignment_spans),
            ("entropy", _entropy_spans),
        )
        for span in ((start, end, rule) for start, end in find(note))
    ]
    return _apply(note, _drop_overlaps(spans))


def entropy(token: str) -> float:
    """Shannon entropy in bits per character."""
    if not token:
        return 0.0
    counts = Counter(token)
    n = len(token)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


def _vendor_spans(note: str):
    return (m.span() for m in _VENDOR_PREFIX.finditer(note))


def _url_spans(note: str):
    return (m.span() for m in _URL_CREDENTIALS.finditer(note))


def _assignment_spans(note: str):
    for match in _ASSIGNMENT.finditer(note):
        key, value = match.group("key"), match.group("value")
        if _PUBLIC_KEY.match(key) or not _SECRET_KEY.search(key):
            continue
        # `api_key = os.environ["PAYMENTS_API_KEY"]` shows how the key is *loaded*
        # and contains no secret. Handoff notes are full of such snippets.
        if "(" in value or "[" in value:
            continue
        if _REFERENCE.match(value) or _PLACEHOLDER.match(value):
            continue
        start, end = match.span("value")
        while end > start and note[end - 1] in ".!?":
            end -= 1
        yield start, end


def _entropy_spans(note: str):
    for match in _TOKEN.finditer(note):
        if _is_secret_shaped(match.group()):
            yield match.span()


def _is_secret_shaped(token: str) -> bool:
    stripped = token.rstrip("=")
    if len(stripped) < _MIN_TOKEN:
        return False

    bits = entropy(stripped)
    if _HEX.fullmatch(stripped):
        return bits >= _HEX_ENTROPY

    classes = sum(
        any(test(c) for c in stripped)
        for test in (str.islower, str.isupper, str.isdigit)
    )
    if classes == 3:
        return bits >= _MIXED_ENTROPY
    return len(stripped) >= _BLOB_LENGTH and bits >= _BLOB_ENTROPY


def _drop_overlaps(spans):
    """Keep the earliest, then longest, span; discard anything overlapping it."""
    kept: list[tuple[int, int, str]] = []
    for span in sorted(spans, key=lambda s: (s[0], -s[1])):
        if kept and span[0] < kept[-1][1]:
            continue
        kept.append(span)
    return kept


def _apply(note: str, spans) -> ScrubResult:
    out: list[str] = []
    redactions: list[Redaction] = []
    cursor = 0
    for start, end, rule in spans:
        out.append(note[cursor:start])
        out.append(REDACTION)
        redactions.append(Redaction(rule, note[start:end], start, end))
        cursor = end
    out.append(note[cursor:])
    return ScrubResult("".join(out), tuple(redactions))
