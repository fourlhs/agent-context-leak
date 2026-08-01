"""Refuse a commit that stages an unscrubbed transcript.

`transcripts/` is committed on purpose — the corpus is part of the benchmark and
has to be reproducible — so an unscrubbed real session is one `git add -A` away
from a permanent public commit. Hard rule 1 says any real transcript is scrubbed
before it comes near this repo; nothing enforced it. This does.

It reads the **staged** bytes, which is what the commit would actually contain: a
file staged clean and then dirtied passes, and one staged dirty and then cleaned
does not.

**The corpus is JSON, and every rule here is written for JSON first.** A rule that
only fires on bare `key=value` is dead on the one format the corpus uses: a
quoted key (`"api_key": "hunter2pass"`), an escaped quote inside an embedded
settings dump, and a doubled backslash in a Windows path all have to match, or
the guard is decorative on the files it exists to guard.

**This is not the C3 scrubber and shares no code with it.** `src/scrubber.py` is a
measured mechanism under test and is deliberately manifest-blind. This is a
safety net for us, so it reads the manifest freely and whitelists the declared
canaries — anything else that looks like a secret is a finding. Coupling them
would contaminate C3: tuning the guard to stop bothering us would silently tune
the thing the experiment measures. `tests/test_transcript_guard.py` asserts the
non-import by parsing this module with `ast`.

The two were written independently and land on some of the same shapes, because
there are only so many shapes a secret takes. Where they differ, **this one is
deliberately the stricter**: a safety net that lets through what the mechanism
under test would catch has it backwards. Hence a vendor prefix with no length
gate, a blob rule tighter than the scrubber's, and a second pass over `/`-joined
runs.

Deliberately noisy rather than clever. A false positive costs one
`CANARY_GUARD_OVERRIDE=1`; a false negative is permanent and public.

One blind spot, stated rather than papered over: a **passphrase** —
`correct-horse-battery-staple` — is word-shaped by construction, so no entropy
rule separates it from an identifier. Its only defence here is the key it sits
behind, which is why `_SECRET_NAME` is generous.
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

# --- vendor prefixes ---------------------------------------------------------
# Our canaries carry none (guardrail 1), so one appearing anywhere is
# unambiguous: no length or entropy gate, unlike the scrubber's equivalent, which
# has to stay plausible as a production rule.
_VENDOR = re.compile(
    r"\b(?:sk_live_|sk_test_|pk_live_|rk_live_|AKIA|ASIA|ghp_|gho_|ghs_|github_pat_"
    r"|xox[baprs]-|AIza|ya29\.|glpat-|npm_|dop_v1_)[A-Za-z0-9_\-]*"
)

# --- credential shapes -------------------------------------------------------
# `(?:\\?")?` after the key is what makes this work on JSON: the closing quote of
# `"api_key"` sits between the name and the colon, and inside an embedded dump it
# arrives escaped as `\"`. The value accepts both forms too.
_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)(?:\\?")?
        \s*[:=]\s*
        (?:\\?"(?P<quoted>[^"\\\n]*)\\?"|'(?P<single>[^'\n]*)'|(?P<bare>[^\s,;'")\]}]+))
    """,
    re.VERBOSE,
)
# `user:pass@host` in a URL. Only the password half is evidence; the host is the
# hostname rule's business.
_URL_CREDENTIAL = re.compile(r"://[^\s/:@]+:(?P<password>[^\s/@]+)@")
# A key whose *name* makes its value a credential whatever the value looks like —
# the only defence against a short or word-shaped one. `key` alone is not here:
# it is a word in prose and a loop variable in code, so the compounds that matter
# are enumerated instead.
_SECRET_NAME = re.compile(
    r"secret|token|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|signing[_-]?key|master[_-]?key|encryption[_-]?key"
    r"|credential|passphrase|auth|dsn|bearer|jwt|hmac|salt",
    re.IGNORECASE,
)
# `api_key = os.environ["PAYMENTS_API_KEY"]` names where a secret is *read from*.
# Transcripts are full of those, and a real value in one is still seen by the
# entropy rule.
_REFERENCE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
_NON_VALUE = re.compile(
    r"<[^>]*>|\[?redacted\]?|x{2,}|\*+|\.{3,}|changeme|todo|tbd|null|none|true|false|\d+",
    re.IGNORECASE,
)
_MIN_VALUE = 6
# Below this an all-letters value is prose — `the secret: rotating it needs a
# ticket` is a sentence. At or above it, an all-letters value is a passphrase.
_PROSE_WORD = 12

# --- randomness --------------------------------------------------------------
# `/` is out of the token class so a path is never one token: `/usr/lib/python3`
# is 16 mixed characters and would otherwise read as random in every traceback.
# `_PATH_RUN` then makes a second pass that *does* span `/`, because a key shaped
# like `wJalrXUtnFEMI/K7MDENG/bPx...` only reads as random when read whole.
_TOKEN = re.compile(r"[A-Za-z0-9+_\-]{16,}={0,2}")
_PATH_RUN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
# An all-lowercase segment is what a path has and a mixed-case secret does not.
# One is enough to call the whole run a path.
_PATH_SEGMENT = re.compile(r"[a-z][a-z0-9]*")
_HEX = re.compile(r"[0-9a-fA-F]+")
# Words and small numbers, joined by separators or by case. `manylinux2014_x86_64`
# and `list_invoices_with_pagination_v2` decompose; `bPxRfiCYEXAMPLEKEY` does not,
# and neither does a near-miss canary, because a hex quad is not a word.
_WORD_PART = re.compile(r"[A-Za-z]{2,}[0-9]{0,4}|[A-Za-z][0-9]{1,4}|[0-9]{1,4}")
_CAMEL_PART = re.compile(r"[A-Z]?[a-z]{2,}|[A-Z]{2,}(?![a-z])|[0-9]{1,4}")
_MIN_TOKEN = 16
_HEX_BITS = 3.0
_MIXED_BITS = 3.5
# The class-poor fallback the scrubber keeps at 32/4.5, tighter here because the
# safety net may not be the weaker of the two. Calibrated against the identifiers
# this corpus actually holds: `SomeVeryLongDescriptiveHandlerName` measures 4.20,
# 24 random lowercase letters measure 4.33.
_BLOB_LENGTH = 24
_BLOB_BITS = 4.0

# --- home directories --------------------------------------------------------
# `\\{1,2}` because JSON stores `C:\Users\name` as `C:\\Users\\name`. Without it
# the rule is silently platform-specific — dead on exactly the machine whose
# paths it exists to catch.
_HOME = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\{1,2}Users\\{1,2})(?P<user>[A-Za-z0-9_.\-]+)")
# A CI runner is not a person's home directory, and its tracebacks get pasted.
_MACHINE_USERS = ("runner", "vsts", "circleci", "travis", "jenkins", "ubuntu", "root")

# --- hostnames ---------------------------------------------------------------
# Four ways a host reaches a file: in a URL, after an address's `@`, bare with a
# real TLD, or as a raw IPv4. The bare TLD list is curated, not exhaustive —
# `deploy.sh`, `lib.rs` and `script.pl` are filenames, so those ccTLDs are left
# out and such a host is caught only in URL or email form. A stated gap.
_URL_HOST = re.compile(r"\b[a-z][a-z0-9+.\-]*://(?:[^\s/@]*@)?([A-Za-z0-9._\-]+)")
_EMAIL_HOST = re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_BARE_HOST = re.compile(
    r"\b((?:[A-Za-z0-9\-]+\.)+(?:com|net|org|io|dev|co|ai|cloud|info|biz|xyz|edu|gov"
    r"|uk|de|fr|nl|eu|ca|au|jp|cn|br|se|no|dk|fi|ie|nz|za|ch|es|it|ru))\b",
    re.IGNORECASE,
)
# A four-part dotted number is an address. Version strings are three parts.
_IPV4 = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
# Hard rule 1: URLs use the reserved TLDs so they can never resolve. Loopback is
# exempt because it cannot carry information anywhere.
_RESERVED = (".example", ".internal")
_LOOPBACK = ("localhost", "0.0.0.0", "::1")


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


def _residue(value: str) -> str:
    """A value with the manifest's own canaries removed.

    Removed, not skipped. A declared canary inside a value must narrow what the
    rule reads, never switch the rule off for the whole value — otherwise
    `password = 'hunter2xyz CANARY-...'` buys silence with one known string, and
    the whitelist has widened a rule instead of narrowing it.
    """
    return value.replace(PLACEHOLDER, "").strip(" \t'\"")


# ------------------------------------------------------------------------ rules


def _vendor_prefix(line: str):
    return (m.group() for m in _VENDOR.finditer(line))


def _credential_shape(line: str):
    """A credential behind a secret-*named* key, assigned or inside a URL.

    The only rule that reaches a short, low-entropy secret — `"api_key":
    "hunter2pass"` is under every length floor the entropy rule has — and the
    only one that reaches a passphrase.
    """
    for match in _URL_CREDENTIAL.finditer(line):
        if _is_credential(match.group("password")):
            yield match.group()
    for match in _ASSIGNMENT.finditer(line):
        value = match.group("quoted") or match.group("single") or match.group("bare") or ""
        if not _SECRET_NAME.search(match.group("key")):
            continue
        # A URL value carries its credential in the `user:pass@host` form handled
        # above, and its host belongs to the hostname rule.
        if "://" in value or "(" in value or "[" in value:
            continue
        if _is_credential(value):
            yield match.group()


def _is_credential(value: str) -> bool:
    rest = _residue(value)
    if len(rest) < _MIN_VALUE or (rest.isalpha() and len(rest) < _PROSE_WORD):
        return False
    return not (_REFERENCE.fullmatch(rest) or _NON_VALUE.fullmatch(rest))


def _entropy(line: str):
    for token in _TOKEN.findall(line):
        if _random_looking(token):
            yield token
    for run in _PATH_RUN.findall(line):
        if "/" in run and not _path_shaped(run) and _random_looking(run):
            yield run


def _home_directory(line: str):
    for match in _HOME.finditer(line):
        user = match.group("user")
        if user != PLACEHOLDER and user.lower() not in _MACHINE_USERS:
            yield match.group()


def _hostname(line: str):
    for pattern in (_URL_HOST, _EMAIL_HOST, _BARE_HOST, _IPV4):
        for match in pattern.finditer(line):
            if not _allowed_host(match.group(1).rstrip(".").lower()):
                yield match.group()


def _allowed_host(host: str) -> bool:
    return host in _LOOPBACK or host.startswith("127.") or host.endswith(_RESERVED)


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


def _path_shaped(run: str) -> bool:
    return any(_PATH_SEGMENT.fullmatch(part) for part in run.split("/") if part)


def _wordy(token: str) -> bool:
    """Does this decompose into words and small numbers?

    Two ways to be a word: separated (`refund_handler_v3_shadow_mode`) or cased
    (`SomeVeryLongDescriptiveHandlerName`). Both are long and varied enough to
    clear an entropy floor and neither is a secret. A passphrase is wordy too —
    see the module docstring; that one is `_SECRET_NAME`'s job.
    """
    parts = re.split(r"[_\-]", token)
    if len(parts) > 1 and all(_WORD_PART.fullmatch(p) for p in parts):
        return True
    cased = _CAMEL_PART.findall(token)
    return len(cased) > 1 and "".join(cased) == token


def _random_looking(token: str) -> bool:
    token = token.strip("=-_")
    if len(token) < _MIN_TOKEN or token == PLACEHOLDER:
        return False
    if _HEX.fullmatch(token):
        return bits(token) >= _HEX_BITS
    if _wordy(token):
        return False
    if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
        return bits(token) >= _MIXED_BITS
    # Class-poor: thirty random letters carry no digit and would otherwise walk
    # past both rules above.
    return len(token) >= _BLOB_LENGTH and bits(token) >= _BLOB_BITS


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
