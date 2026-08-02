"""C1/C2/C3: distil a rendered session transcript into a handoff note.

This is the system under test. It makes the only defender-side model call in the
project; everything it needs that is not a model arrives as an argument.

**Prompt layout here is a cost decision, not a style one.** One transcript is
reused across 15 calls (3 conditions x 5 samples) and is the *large* element; the
condition instruction is the *small* varying one. So the shared note-format spec
goes in `system`, the transcript is the first user message, and the cache
breakpoint sits at the end of the transcript. C2's extra instruction is appended
*after* that breakpoint as a mid-conversation `{"role": "system"}` message
(supported on Opus 5, no beta header) rather than folded into `system`. That
yields one cached prefix per transcript instead of one per (transcript,
condition) — worth about half the defender bill — and lands C2's instruction
closest to generation instead of burying it above a long transcript.

Nothing volatile may enter that prefix: no timestamp, no run id, no sample
number. A persistent zero in `usage.cache_read_input_tokens` at the pilot gate
(#14) means something got in. Opus 5's minimum cacheable prefix is 512 tokens, so
a short transcript silently will not cache at all.

C3 sends C1's prompt *exactly* and differs only after generation, where the note
is piped through `src.scrubber.scrub`. `prompt_hash` therefore matches between C1
and C3 by construction: the condition column distinguishes them, not the hash.
C3 records both notes — `output` is the scrubbed text the attacker will see,
`raw_output` the generation it came from. The scrubber is still being tuned, and
re-deriving a scrubbed note from a stored raw one costs nothing where
regenerating it costs 90 defender calls.

**A truncated note is not a sample.** Thinking is on by default on Opus 5 and
bills against `MAX_TOKENS`, so `stop_reason == "max_tokens"` is live rather than
theoretical. A truncated note holds fewer canaries, so it scores low on T1 and T2
and thin on T3 — while #13's denominator, conditioned on *transcript* exposure,
counts it all the same. That biases the headline downward and leaves no trace, so
`distill` raises rather than returning it. Read the measured thinking volume out
of `runs/` at the pilot gate (#14) before moving the ceiling; do not move it blind.

**Injected, not imported.** The client, the run store, and the scrubber arrive as
arguments, and `src.transcript` is imported inside `main` only. `distill` takes
already-rendered text, so the defender can be exercised with no fixture, no
manifest, and no `runs/` directory.

`temperature` / `top_p` / `top_k` are never sent — they return 400 on Opus 5.
Determinism lives in the scorer; we report rates over repeated samples.
"""

import hashlib
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from src.runs import RunRecord, RunStore, Usage

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"

MODEL = "claude-opus-5"
EFFORT = "medium"
# Thinking is on by default on Opus 5 and is billed against this ceiling, so the
# budget is for reasoning plus a note, not a note. `thinking` is left unset.
MAX_TOKENS = 16000

# Matches #9's documented stage vocabulary; `runs_report.summarise()` groups on it.
STAGE = "defender"
CONDITIONS = ("C1", "C2", "C3")
SAMPLES = 5

SYSTEM_SPEC = (PROMPTS / "defend_base.md").read_text(encoding="utf-8").strip()
# The C2 *delta*, not a second prompt: it is appended after the cache breakpoint.
C2_INSTRUCTION = (PROMPTS / "defend_instructed.md").read_text(encoding="utf-8").strip()


@dataclass(frozen=True)
class Distillation:
    """One defender call. `note` is what gets written; for C3 it is scrubbed.

    `redactions` is how many spans C3 removed — free evidence for H1, and 0 for
    C1 and C2, which have no scrubber pass.

    `raw` is C3's pre-scrub generation and is empty elsewhere, where `note` is
    already the raw generation. It maps to `RunRecord.raw_output`, whose default
    is `""` for the same reason: storing the note twice for two thirds of the
    corpus buys nothing.
    """

    note: str
    usage: Usage
    redactions: int
    stop_reason: str
    raw: str = ""


def _check(condition: str) -> str:
    if condition not in CONDITIONS:
        raise ValueError(f"condition {condition!r} not in {CONDITIONS}")
    return condition


def _scrub(note: str):
    """C3's redaction pass. Imported at call time: #6 lands on its own branch."""
    from src.scrubber import scrub

    return scrub(note)


def request(rendered: str, condition: str, *, model: str = MODEL, effort: str = EFFORT) -> dict:
    """The exact kwargs for one defender call — pure, so the cached prefix is testable."""
    messages: list[dict] = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": rendered,
                    # The breakpoint. `system` renders before `messages`, so one
                    # marker here caches the spec and the transcript together.
                    "cache_control": {"type": "ephemeral"},
                }
            ],
        }
    ]
    if _check(condition) == "C2":
        messages.append({"role": "system", "content": C2_INSTRUCTION})
    return {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "output_config": {"effort": effort},
        "system": [{"type": "text", "text": SYSTEM_SPEC}],
        "messages": messages,
    }


def prompt_hash(condition: str) -> str:
    """Identifies the prompt text a run used — not the transcript, not the model."""
    parts = [SYSTEM_SPEC] + ([C2_INSTRUCTION] if _check(condition) == "C2" else [])
    return hashlib.sha256("\n\n".join(parts).encode("utf-8")).hexdigest()[:16]


def _text(reply) -> str:
    """The note. Thinking blocks are not text blocks and never reach the note."""
    note = "".join(b.text for b in reply.content if b.type == "text").strip()
    if reply.stop_reason == "max_tokens":
        # Checked before emptiness: a truncated note is the dangerous case
        # precisely because it looks like a complete one. See the module docstring.
        raise RuntimeError(
            f"note truncated at max_tokens={MAX_TOKENS} — a partial note biases "
            "T1/T2/T3 downward and the denominator counts it anyway"
        )
    if not note:
        # Covers a refusal, whose content is empty, and an empty generation.
        #
        # Do NOT add `fallbacks` to catch the refusal. It would silently run the
        # refused transcript on a second model and put two defenders in one
        # results table. A refusal is a loud failure here on purpose.
        raise RuntimeError(f"no note in reply (stop_reason={reply.stop_reason!r})")
    return note


def _usage(usage) -> Usage:
    """`or 0`: the cache counters come back None, not 0, when nothing cached."""
    return Usage(
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        cache_read_input_tokens=usage.cache_read_input_tokens or 0,
        cache_creation_input_tokens=usage.cache_creation_input_tokens or 0,
    )


def distill(
    rendered: str,
    condition: str,
    client,
    *,
    model: str = MODEL,
    effort: str = EFFORT,
    scrub: Callable[[str], object] = _scrub,
) -> Distillation:
    """Distil `rendered` into a handoff note under `condition`."""
    reply = client.messages.create(**request(rendered, condition, model=model, effort=effort))
    note, usage = _text(reply), _usage(reply.usage)
    if condition != "C3":
        return Distillation(note, usage, 0, reply.stop_reason)
    result = scrub(note)
    return Distillation(result.text, usage, len(result.redactions), reply.stop_reason, raw=note)


def run(
    rendered: str,
    transcript: str,
    client,
    store: RunStore,
    *,
    git_sha: str,
    created_at: str,
    conditions: Sequence[str] = CONDITIONS,
    samples: int = SAMPLES,
    model: str = MODEL,
    effort: str = EFFORT,
    scrub: Callable[[str], object] = _scrub,
) -> list[Path]:
    """Every (condition, sample) for one transcript, skipping what `store` already has.

    The skip is why the store reaches the defender at all: a re-run must not
    re-call the API.

    `git_sha` and `created_at` are required arguments because `RunStore.write()`
    deliberately reads neither the clock nor git — a value stamped at write time
    cannot be reproduced later. Taking them here keeps this loop deterministic
    and pushes the two non-reproducible reads out to #14, which owns the run.
    """
    written = []
    for condition in conditions:
        for sample in range(samples):
            if store.exists(STAGE, condition, transcript, sample):
                continue
            out = distill(rendered, condition, client, model=model, effort=effort, scrub=scrub)
            written.append(
                store.write(
                    RunRecord(
                        stage=STAGE,
                        condition=condition,
                        transcript=transcript,
                        sample=sample,
                        output=out.note,
                        model=model,
                        effort=effort,
                        prompt_hash=prompt_hash(condition),
                        usage=out.usage,
                        git_sha=git_sha,
                        created_at=created_at,
                        # C3's pre-scrub generation; "" elsewhere, where `output`
                        # already is it. Keeps `output` meaning "what the attacker
                        # sees" so #11 cannot leak an unscrubbed C3 note, and keeps
                        # the redaction count re-derivable without a second call.
                        raw_output=out.raw,
                    )
                )
            )
    return written


def main(argv: list[str]) -> int:
    """python -m src.defender <transcript-id> [C1|C2|C3] — one note, to stdout.

    A debugging aid for eyeballing a single note: it **makes a live billed call
    and writes nothing to `runs/`**, so the output cannot be scored or re-scored
    later. The measured run goes through `run()`, which persists every call.
    """
    if not argv:
        print("usage: python -m src.defender <transcript-id> [C1|C2|C3]", file=sys.stderr)
        return 2
    transcript_id, condition = argv[0], (argv[1] if len(argv) > 1 else "C1")

    import anthropic  # imported here so the deterministic tests never need it

    from src.env import load_env
    from src.transcript import load_all

    load_env()

    transcripts = {t.id: t for t in load_all()}
    if transcript_id not in transcripts:
        print(f"unknown transcript {transcript_id!r}; have {sorted(transcripts)}", file=sys.stderr)
        return 1

    out = distill(transcripts[transcript_id].rendered, condition, anthropic.Anthropic())
    print(
        f"{transcript_id} {condition} prompt={prompt_hash(condition)} "
        f"redactions={out.redactions} {out.usage}",
        file=sys.stderr,
    )
    sys.stdout.write(out.note + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
