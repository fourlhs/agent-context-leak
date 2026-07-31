You are ending a working session. Write the handoff note that the next agent — or you
tomorrow, with none of today's context — reads before touching this work.

Output the note and nothing else: no preamble, no closing remarks, no commentary about
the note itself.

## Sections

Use these four headings, in this order, and no others. A section with nothing to report
gets the single word `None.` — never drop it, never fold it into another.

### What changed

The difference this session made: what the behaviour was, what it is now, and where in
the code that difference lives. Name files, functions, commands, and configuration keys
the way they are actually spelled — the reader is going to search for them.

### What was tried and rejected, and why

The approaches this session considered and abandoned, each with the evidence that killed
it.

**This is the section that earns the note its keep, and it is the easiest one to ruin.**
It is not a log of steps taken; it is a map of closed doors. An entry belongs here only
if it stops the next reader from proposing something that has already failed. Work you
finished is not a rejection. Neither is a step you took on the way to the thing that
worked.

Give the approach, then what happened to it. Be specific about the evidence: "too slow"
is not a rejection, "24s against a 5s timeout" is. If a rejection rests on something that
has since changed, say so — a stale closed door costs more than an open one.

### Open questions

Decisions still outstanding, each with what it hinges on and what would settle it. "Not
built yet" is not an open question; "not decided yet" is.

### Gotchas

What will bite someone who does not already know it: surprising behaviour, ordering that
matters, sharp edges in the environment, code that looks wrong and is right. Give the
trigger, not only the symptom.

## How to write it

- Report what this session actually observed. Where something was assumed rather than
  checked, say which.
- Quote the real thing — the error text, the command, the identifier — rather than
  paraphrasing it. A reader who cannot reproduce your wording cannot find what you mean.
- Let length follow content. Do not pad a thin section to look thorough, and do not
  compress a section that has real content into fragments.
- Write for someone competent who was not here. Shorthand you invented mid-session means
  nothing to them unless you reintroduce it.
