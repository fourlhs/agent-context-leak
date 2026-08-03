"""Refuse a commit that stages a real value in a file this repo publishes.

Two directories are in scope, for the same reason. Both are committed on purpose
— the corpus is part of the benchmark and has to be reproducible, the manifest is
the single source of truth — so an unscrubbed real session pasted into one, or a
real key typed into the other while authoring a canary, is one `git add -A` away
from a permanent public commit. Hard rule 1 says everything here is synthetic;
nothing enforced it. This does.

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
gate, a PEM header with no gate at all, a blob rule tighter than the scrubber's,
a `_wordy` exemption that spares no encoding the scrubber would catch (#62), and
a second pass over `/`-joined runs.

**Where the line is on the manifest (#51). This paragraph is the authoritative
statement of it; `README.md` and `CLAUDE.md` summarise and point here.**

`canaries/manifest.yaml` is *supposed* to hold secret-shaped strings — that is
what a canary is — so a guard over it needs a rule for which ones are legitimate,
and a guard that trusted the whole file would be a decoration. The line is
`redact()` plus `manifest.validate()`: a string passes iff the manifest declares
it as a `canary_string`, an `entropy_tail`, or the `planted_value` those two
compose, **and** `validate()` accepted the declaration. Everything outside those
three fields — contexts, markers, target paths, and **comments** — is read
exactly as a transcript is.

**What that closes, and what it does not.** The whitelist is drawn from the file
under inspection, so its width is exactly `validate()`'s width, and `validate()`
is uneven:

- `canary_string` is **closed**. It must match `CANARY-<4 hex>-<CATEGORY>` with
  the suffix equal to the declared category, so no real credential shape fits.
- A **non-hex** tail is closed. `sk_live_...`, base64, a mixed-case blob: refused.
- A **lowercase-hex** tail is **accepted on its face, and that is a real hole.**
  Hex is the native encoding of a large class of real credentials, and nothing
  here can tell a synthetic 16-hex run from a stolen one. #51 narrowed
  `manifest._TAIL` to `[0-9a-f]{8,20}`, which refuses the 32/40/64-hex shapes
  that most real hex credentials take — every canary here uses 16 — but 8-to-20
  hex still validates and is still whitelisted.

The blast radius of that hole is the whole scope, not just the manifest:
`declared()` feeds `redact()` for **every** file checked, so a real secret
committed as a tail is thereafter invisible in transcripts too. It is the reason
the ceiling exists and the reason this paragraph does not claim more than it can.

**The whitelist comes from what the commit will contain, never from the working
tree.** `_staged_canaries` reads the manifest from the index when it is staged
and from `HEAD` when it is not, which is precisely the manifest the commit ends
up with. Sourcing it from disk instead — as this did before review — let an
**unstaged** edit widen the whitelist for content that *was* staged: declaring a
secret as a tail without ever committing that declaration made the same secret
pass inside a transcript. Nothing constrains an unreviewed working-tree file, so
"synthetic by construction" was never true of one.

Comments are not exempt, deliberately. Exempting them is the cheap way to quiet
an illustrative path in the manifest header, and it buys that quiet by going
blind to a real secret pasted into a comment, which is committed and public just
the same. The header illustrates the path format with a declared canary instead.
The cost is real and is stated with the rule in the manifest header: the manifest
can never cite an external URL or hostname, because a comment naming this repo on
GitHub or quoting a real documentation link fires the hostname rule.

Deliberately noisy rather than clever. A false positive costs one
`CANARY_GUARD_OVERRIDE=1`; a false negative is permanent and public.

Two blind spots, stated rather than papered over. A **passphrase** —
`correct-horse-battery-staple` — is word-shaped by construction, so no entropy
rule separates it from an identifier; its only defence here is the key it sits
behind, which is why `_SECRET_NAME` is generous. And a **short blob** is bounded
by the entropy floor rather than by any exemption. Now that `_wordy` spares no
encoding (#62), a random 32-character base32 run is missed 0.10% of the time and
a 40-character one 0.00%, but a 16-character one — the length a TOTP seed comes
in — still passes 31.26%, because 16 characters drawn from 32 symbols often do
not reach `_MIXED_BITS`; the canonical published demo seed measures 3.375 bits
and passes every time. Before #62 the same three lengths read 65.60%, 32.10% and
25.70%, the exemption being the whole of the miss at the two longer ones. 5000
samples per length, alphabet `A-Z234567` and its lowercase twin (which score
identically, the two case branches being symmetric), seed 62.
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

import yaml

from src.manifest import Canary
from src.manifest import load as load_canaries
from src.manifest import loads

# The file that supplies the whitelist, and is itself in scope.
MANIFEST = "canaries/manifest.yaml"

# Which staged paths are checked, and the one deliberate way past a finding.
# `git commit --no-verify` is too invisible to count as a decision. An inclusion
# list protects only what someone remembered to add, which is why #59 asks
# whether the default should be inverted.
SCOPE = ("canaries/", "transcripts/")
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

# --- private keys ------------------------------------------------------------
# A PEM header, which is the most recognisable real-secret marker there is and
# one no canary can produce, so like a vendor prefix it gets no length or entropy
# gate. The body is base64 wrapped at 64 columns and the entropy rule reaches it
# or not depending on where the line breaks fall; the header does not depend on
# anything. `[A-Z0-9 ]*` covers the family — RSA, DSA, EC, OPENSSH, ENCRYPTED,
# PGP's ` BLOCK` suffix, and the bare `PRIVATE KEY` of a PKCS#8 file.
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")

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
    r"|credential|passphrase|auth|dsn|bearer|jwt|hmac|salt|session|cookie",
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


def _private_key(line: str):
    return (m.group() for m in _PEM.finditer(line))


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
    ("private_key", _private_key),
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

    **The cased branch takes letters only (#62), and the digit is the whole
    point.** A separator is a word boundary somebody typed, so digits are fine
    beside one — `manylinux2014_x86_64` keeps its exemption. Inside a
    run-together token nothing marks a boundary but case, and a digit there is
    not a word break, it is an encoding: base32's `2-7` are exactly what split
    `JBSWY3DPEHPK3PXP` into "words", and a digit-free base32 run cannot decompose
    at all, because one unbroken case run is a single part. The cost is that a
    run-together *cased* name carrying a digit — `Sha256DigestHandler` — is now a
    finding, which is the trade this guard takes by design.
    """
    parts = re.split(r"[_\-]", token)
    if len(parts) > 1 and all(_WORD_PART.fullmatch(p) for p in parts):
        return True
    cased = _CAMEL_PART.findall(token)
    return token.isalpha() and len(cased) > 1 and "".join(cased) == token


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


def staged(scope: str | tuple[str, ...] = SCOPE) -> tuple[str, ...]:
    """Paths added, copied, modified or renamed in the index — not the working tree.

    `R` is in the filter because a rename is how content that was never checked
    here arrives here. `str.startswith` takes the tuple as-is, so a scope of one
    directory and a scope of several are the same code path.
    """
    listing = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return tuple(p for p in listing.split("\0") if p.startswith(scope))


def check_staged(
    canaries: Iterable[Canary], scope: str | tuple[str, ...] = SCOPE
) -> tuple[Finding, ...]:
    """`git show :path` is the staged blob; reading the file would miss the point."""
    canaries = tuple(canaries)
    return tuple(
        finding
        for path in staged(scope)
        for finding in check_text(_git("show", f":{path}"), canaries, path=path)
    )


def committed_canaries() -> tuple[Canary, ...]:
    """The manifest as the commit will contain it — the index, never the disk.

    `:path` is the index entry, which for a staged manifest is the new version
    and for an untouched one is HEAD's. Either way it is what the commit ends up
    with, so the whitelist and the content it is applied to come from the same
    artefact. Reading the working tree instead let an **unstaged** edit widen the
    whitelist for content that *was* staged — see the docstring.

    An empty whitelist where the manifest is not in the index at all: no commit,
    no declared canary, nothing legitimate to let through.
    """
    try:
        return loads(_git("show", f":{MANIFEST}"))
    except RuntimeError:
        return ()


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
        f"Hard rule 1: everything committed here is synthetic -- a real transcript is "
        f"scrubbed before it comes near this repo, and a canary is invented rather than "
        f"pasted. Hard rule 3: this repo is public and what lands here is permanent, so "
        f"an unscrubbed commit cannot be taken back."
    )


def unrunnable(reason: str, *, overridden: bool) -> str:
    """The guard could not run at all — almost always an unloadable manifest.

    Blocking is right: with no whitelist there is nothing to check against. But
    it has to block the way a finding blocks, through a message that names the
    override, rather than through a traceback whose only escape is `--no-verify`
    — which this repo's own hook calls too invisible to count as a decision.

    Before #51 an unloadable manifest was a rare coincidence. Now the manifest is
    the file people are editing when the hook fires, and half-finished is its
    normal intermediate state, so this path is ordinary rather than exceptional.
    """
    # The reason is somebody else's prose -- `manifest.validate()` writes em
    # dashes -- and `verdict`'s ASCII rule applies to whatever this prints.
    where = f"transcript-guard: cannot run -- {reason.encode('ascii', 'replace').decode()}"
    if overridden:
        return f"{where}\nAllowed because {OVERRIDE}=1 is set. Nothing was checked."
    return (
        f"{where}\nCommit blocked: with no canary manifest there is no whitelist, so "
        f"nothing can be checked.\n"
        f"Fix the manifest, or re-run the commit with {OVERRIDE}=1 to commit unchecked."
    )


def _findings(paths: list[str]) -> tuple[Finding, ...]:
    if not paths:
        return check_staged(committed_canaries())
    # Manual review reads the manifest off disk: the file named may be anywhere,
    # including outside a repository, and there is no commit to agree with.
    canaries = load_canaries()
    return tuple(
        finding
        for path in paths
        for finding in check_text(
            Path(path).read_text(encoding="utf-8", errors="replace"), canaries, path=path
        )
    )


def main(argv: list[str]) -> int:
    overridden = os.environ.get(OVERRIDE) == "1"
    try:
        findings = _findings([a for a in argv if not a.startswith("-")])
    except (OSError, RuntimeError, ValueError, yaml.YAMLError) as exc:
        print(unrunnable(f"{type(exc).__name__}: {exc}", overridden=overridden), file=sys.stderr)
        return 0 if overridden else 1
    for finding in findings:
        print(finding, file=sys.stderr)
    if not findings:
        return 0
    print(verdict(findings, overridden=overridden), file=sys.stderr)
    return 0 if overridden else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
