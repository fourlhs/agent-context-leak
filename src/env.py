"""Find the API key without putting it in version control.

`.env` is gitignored, which is the same boundary the experiment is about: the
file never enters a commit, and nothing here ever reads its contents into a
string it might print. The load happens at the entry points rather than at
import, so the deterministic core still runs with no key, no network, and no
opinion about the environment.
"""

from pathlib import Path

from dotenv import load_dotenv

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def load_env() -> None:
    """Load `.env` into the environment if it is there, and say nothing about it.

    `override=False` so a real environment variable always wins: `ANTHROPIC_API_KEY=...
    uv run ...`, a CI secret, and a shell export all beat a stale file, which is
    the order of surprise people expect. Pinned to the repo root rather than
    discovered from the working directory, so a run from anywhere finds the same
    file — or finds nothing, which `load_dotenv` treats as fine.
    """
    load_dotenv(ENV_FILE, override=False)
