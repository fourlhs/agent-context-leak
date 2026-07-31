"""Refuse a commit that stages an unscrubbed transcript.

`transcripts/` is committed on purpose — the corpus is part of the benchmark and
has to be reproducible — so an unscrubbed real session is one `git add -A` away
from a permanent public commit. Hard rule 1 says any real transcript is scrubbed
before it comes near this repo; nothing enforced it. This does.

It reads the **staged** bytes, which is what the commit would actually contain: a
file staged clean and then dirtied passes, and one staged dirty and then cleaned
does not.

**This is not the C3 scrubber and shares no code with it.** `src/scrubber.py` is a
measured mechanism under test and is deliberately manifest-blind. This is a
safety net for us, so it reads the manifest freely and whitelists the twelve
declared canaries — anything else that looks like a secret is a finding. Coupling
them would contaminate C3: tuning the guard to stop bothering us would silently
tune the thing the experiment measures. `tests/test_transcript_guard.py` asserts
the non-import by parsing this module with `ast`.

Deliberately noisy rather than clever. A false positive costs one `CANARY_GUARD_OVERRIDE=1`;
a false negative is permanent and public.
"""

import math
import os
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from src.manifest import Canary
from src.manifest import load as load_canaries

# Which staged paths are checked, and the one deliberate way past a finding.
# `git commit --no-verify` is too invisible to count as a decision.
SCOPE = "transcripts/"
OVERRIDE = "CANARY_GUARD_OVERRIDE"

# What every declared canary collapses to before a rule sees the text. 15 chars
# with no digit, so it is below _MIN_TOKEN and trips nothing by itself.
PLACEHOLDER = "CANARY_DECLARED"

_SNIPPET = 90

# Vendor prefixes. Our canaries deliberately carry none (guardrail 1), so one
# appearing anywhere is unambiguous — no length or entropy gate, unlike the
# scrubber's equivalent, which has to stay plausible as a production rule.
_VENDOR = re.compile(
    r"\b(?:sk_live_|sk_test_|pk_live_|rk_live_|AKIA|ASIA|ghp_|gho_|ghs_|github_pat_"
    r"|xox[baprs]?-?|AIza|ya29\.|glpat-|npm_|dop_v1_)[A-Za-z0-9_\-]*"
)

_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)
        \s*[:=]\s*
        (?:"(?P<quoted>[^"\n]*)"|'(?P<single>[^'\n]*)'|(?P<bare>[^\s,;'")\]}]+))
    """,
    re.VERBOSE,
)
_SECRET_NAME = re.compile(
    r"secret|token|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|credential|auth|dsn|bearer",
    re.IGNORECASE,
)
_MIN_VALUE = 6

# `/` is out of the token class so a path is never one token: `/usr/lib/python3`
# is 16 mixed characters and would otherwise read as random in every traceback.
# The cost is a base64 run that happens to split on a `/`, and each half of one
# long enough to matter is still over _MIN_TOKEN. `=` is allowed only as base64
# padding, so a token can never span `key=value` and read the pair as one blob.
_TOKEN = re.compile(r"[A-Za-z0-9+_\-]{16,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]+")
# A snake_case or kebab-case identifier — `absolute_path_with_username_01`,
# `test_refund_500_handler` — is long and varied enough to clear the entropy
# floor. Secrets do not decompose into words, so decomposition is the cheap
# discriminator; a near-miss canary (`CANARY-7F3A-...`) does not survive it,
# because a hex quad is neither a word nor a small number.
_IDENTIFIER_PART = re.compile(r"[A-Za-z]{2,}|[0-9]{1,4}")
_MIN_TOKEN = 16
_HEX_BITS = 3.0
_MIXED_BITS = 3.5

_HOME = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)(?P<user>[A-Za-z0-9_.\-]+)")

# Three ways a hostname reaches a file: in a URL, after an address's `@`, or bare
# with a real TLD. The bare list is short on purpose — `deploy.sh` and
# `settings.local` are filenames, and a rule that flagged them would be off by
# the end of the week.
_URL_HOST = re.compile(r"\b[a-z][a-z0-9+.\-]*://(?:[^\s/@]*@)?([A-Za-z0-9._\-]+)")
_EMAIL_HOST = re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_BARE_HOST = re.compile(
    r"\b((?:[A-Za-z0-9\-]+\.)+(?:com|net|org|io|dev|co|ai|app|cloud|info|biz|xyz|edu|gov))\b",
    re.IGNORECASE,
)
# Hard rule 1: URLs use the reserved TLDs so they can never resolve. Loopback is
# exempt because it cannot carry information anywhere.
_RESERVED = (".example", ".internal")
_LOOPBACK = ("localhost", "127.0.0.1", "0.0.0.0", "::1")


@dataclass(frozen=True)
class Finding:
    """One reason a file looks unscrubbed: which rule fired, and where."""

    path: str
    line: int
    rule: str
    text: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.text}"


# ------------------------------------------------------------------- whitelist


def declared(canaries: Iterable[Canary]) -> tuple[str, ...]:
    """Every string the manifest legitimises, longest first so `re` prefers it."""
    tokens = {
        token
        for c in canaries
        for token in (c.planted_value, c.canary_string, c.entropy_tail)
        if token
    }
    return tuple(sorted(tokens, key=len, reverse=True))


def redact(text: str, canaries: Iterable[Canary]) -> str:
    """Collapse declared canaries to `PLACEHOLDER` so only strangers are left."""
    tokens = declared(canaries)
    if not tokens:
        return text
    return re.sub("|".join(re.escape(t) for t in tokens), PLACEHOLDER, text)


# ------------------------------------------------------------------------ rules


def _vendor_prefix(line: str):
    return (m.group() for m in _VENDOR.finditer(line))


def _credential_shape(line: str):
    """`KEY=value` where the key's *name* makes the value a credential.

    A value that is purely alphabetic is skipped: transcripts are mostly prose,
    and `the secret: rotating it needs a ticket` is a sentence, not a key. Real
    credentials mix classes, and the entropy rule sees them anyway.
    """
    for match in _ASSIGNMENT.finditer(line):
        value = match.group("quoted") or match.group("single") or match.group("bare") or ""
        if not _SECRET_NAME.search(match.group("key")):
            continue
        if len(value) < _MIN_VALUE or value.isalpha() or PLACEHOLDER in value:
            continue
        yield match.group()


def _entropy(line: str):
    return (token for token in _TOKEN.findall(line) if _random_looking(token))


def _home_directory(line: str):
    return (m.group() for m in _HOME.finditer(line) if m.group("user") != PLACEHOLDER)


def _hostname(line: str):
    for pattern in (_URL_HOST, _EMAIL_HOST, _BARE_HOST):
        for match in pattern.finditer(line):
            host = match.group(1).rstrip(".").lower()
            if host not in _LOOPBACK and not host.endswith(_RESERVED):
                yield match.group()


RULES = (
    ("vendor_prefix", _vendor_prefix),
    ("credential_shape", _credential_shape),
    ("entropy", _entropy),
    ("home_directory", _home_directory),
    ("hostname", _hostname),
)


def bits(token: str) -> float:
    """Shannon entropy in bits per character."""
    counts = Counter(token)
    return -sum((n / len(token)) * math.log2(n / len(token)) for n in counts.values())


def _identifier_shaped(token: str) -> bool:
    parts = re.split(r"[_\-]", token)
    return len(parts) > 1 and all(_IDENTIFIER_PART.fullmatch(p) for p in parts)


def _random_looking(token: str) -> bool:
    token = token.strip("=-_")
    if len(token) < _MIN_TOKEN or token == PLACEHOLDER:
        return False
    if _HEX.fullmatch(token):
        return bits(token) >= _HEX_BITS
    if _identifier_shaped(token):
        return False
    has = (any(c.isdigit() for c in token), any(c.isalpha() for c in token))
    return all(has) and bits(token) >= _MIXED_BITS


# ------------------------------------------------------------------- inspection


def check_text(
    text: str, canaries: Iterable[Canary], *, path: str = "<text>"
) -> tuple[Finding, ...]:
    """Every rule, every line. Line numbers are 1-based, as an editor reports them."""
    canaries = tuple(canaries)
    return tuple(
        Finding(path, number, rule, hit[:_SNIPPET])
        for number, line in enumerate(redact(text, canaries).splitlines(), 1)
        for rule, find in RULES
        for hit in find(line)
    )


def _git(*args: str) -> str:
    done = subprocess.run(("git", *args), capture_output=True, encoding="utf-8", errors="replace")
    if done.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout


def staged(scope: str = SCOPE) -> tuple[str, ...]:
    """Paths added, copied, modified or renamed in the index — not the working tree.

    `R` is in the filter because a rename is how content that was never checked
    here arrives here.
    """
    listing = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return tuple(p for p in listing.split("\0") if p.startswith(scope))


def check_staged(canaries: Iterable[Canary], scope: str = SCOPE) -> tuple[Finding, ...]:
    """`git show :path` is the staged blob; reading the file would miss the point."""
    canaries = tuple(canaries)
    return tuple(
        finding
        for path in staged(scope)
        for finding in check_text(_git("show", f":{path}"), canaries, path=path)
    )


# --------------------------------------------------------------------------- cli


def verdict(findings: tuple[Finding, ...], *, overridden: bool) -> str:
    """ASCII only: this is the one message that must survive a Windows console."""
    where = f"{len(findings)} finding(s) in {len({f.path for f in findings})} file(s)"
    if overridden:
        return f"transcript-guard: {where}, allowed because {OVERRIDE}=1 is set."
    return (
        f"transcript-guard: {where} -- commit blocked.\n"
        f"Scrub the file. If every finding above is a false positive, re-run the commit "
        f"with {OVERRIDE}=1 in the environment.\n"
        f"Hard rule 1: any real transcript is scrubbed before it comes near this repo. "
        f"Hard rule 3: this repo is public and what lands here is permanent, so an "
        f"unscrubbed commit cannot be taken back."
    )


def main(argv: list[str]) -> int:
    canaries = load_canaries()
    paths = [a for a in argv if not a.startswith("-")]
    findings = (
        tuple(
            finding
            for path in paths
            for finding in check_text(
                Path(path).read_text(encoding="utf-8", errors="replace"), canaries, path=path
            )
        )
        if paths
        else check_staged(canaries)
    )
    for finding in findings:
        print(finding, file=sys.stderr)
    if not findings:
        return 0
    overridden = os.environ.get(OVERRIDE) == "1"
    print(verdict(findings, overridden=overridden), file=sys.stderr)
    return 0 if overridden else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
