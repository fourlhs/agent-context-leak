import json
import os
from dataclasses import replace

import pytest

from src import attacker, defender
from src.runs import RUNS, RunRecord, RunStore, Usage, failed

USAGE = Usage(
    input_tokens=1200,
    output_tokens=300,
    cache_read_input_tokens=8000,
    # Zero, and it still has to survive the round trip: a provider returning 0
    # is not the same as a field that was never recorded.
    cache_creation_input_tokens=0,
)

RECORD = RunRecord(
    stage="defender",
    condition="C1",
    transcript="t01",
    sample=0,
    output="Picked up the retry loop; credentials load from the environment.",
    model="claude-opus-5",
    effort="medium",
    prompt_hash="a1b2c3d4",
    usage=USAGE,
    git_sha="0123456789abcdef0123456789abcdef01234567",
    created_at="2026-07-31T21:04:00+00:00",
)

STAGES = ("defender", "attacker", "control")
CONDITIONS = ("C1", "C2", "C3", "")

JOBS = (("t01", "C1", 0), ("t01", "C1", 1), ("t02", "C3", 0))


class FakeClient:
    """Stands in for the model call. Counts calls, so resume is asserted on
    what was *spent*, not on what happens to be on disk."""

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, transcript: str, condition: str, sample: int):
        self.calls += 1
        return f"note {transcript}/{condition}/{sample}", USAGE


def drive(store: RunStore, client: FakeClient, jobs=JOBS) -> None:
    """The resume gate every model-calling stage shares: `exists()` before the
    request, so a completed call is never re-billed."""
    for transcript, condition, sample in jobs:
        if store.exists("defender", condition, transcript, sample):
            continue
        output, usage = client.generate(transcript, condition, sample)
        store.write(
            replace(
                RECORD,
                transcript=transcript,
                condition=condition,
                sample=sample,
                output=output,
                usage=usage,
            )
        )


@pytest.fixture
def store(tmp_path):
    return RunStore(tmp_path)


def test_default_root_is_the_repo_runs_dir_and_tests_never_write_it():
    assert RunStore().root == RUNS
    assert RUNS.name == "runs"


def test_write_then_read_all_round_trips(store):
    path = store.write(RECORD)

    assert path == store.path_for("defender", "C1", "t01", 0)
    assert store.read_all() == (RECORD,)


def test_raw_output_round_trips(store):
    # C3 keeps the pre-scrub generation here so re-tuning the scrubber
    # re-scores off disk instead of re-calling the defender 90 times.
    scrubbed = replace(RECORD, output="KEY=[REDACTED]", raw_output="KEY=abc123def456")

    store.write(scrubbed)

    assert store.read_all() == (scrubbed,)
    assert store.read_all()[0].raw_output == "KEY=abc123def456"


def test_record_written_without_raw_output_still_loads(store):
    path = store.write(RECORD)
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["raw_output"]  # a record from before the field existed
    path.write_text(json.dumps(data), encoding="utf-8")

    assert store.read_all() == (RECORD,)
    assert store.read_all()[0].raw_output == ""


def test_record_json_carries_all_four_usage_fields(store):
    path = store.write(RECORD)

    usage = json.loads(path.read_text(encoding="utf-8"))["usage"]
    assert usage == {
        "input_tokens": 1200,
        "output_tokens": 300,
        "cache_read_input_tokens": 8000,
        "cache_creation_input_tokens": 0,
    }


def test_exists_is_false_before_and_true_after(store):
    assert not store.exists("defender", "C1", "t01", 0)

    store.write(RECORD)

    assert store.exists("defender", "C1", "t01", 0)


def test_read_returns_the_record_or_none(store):
    key = ("defender", "C1", "t01", 0)

    assert store.read(*key) is None

    store.write(RECORD)

    assert store.read(*key) == RECORD


def test_exists_cannot_see_a_provenance_change_but_read_can(store):
    """Pins the known limit of the resume gate. `exists()` keys on the four
    coordinates, so a driver relaunching at a new effort must compare the
    record itself or it will keep the old one and call nothing."""
    store.write(RECORD)

    assert store.exists("defender", "C1", "t01", 0)  # blind to effort
    assert store.read("defender", "C1", "t01", 0).effort == "medium"


def test_second_pass_makes_zero_calls(store):
    client = FakeClient()

    drive(store, client)
    assert client.calls == len(JOBS)

    drive(store, client)
    assert client.calls == len(JOBS)  # the whole point: nothing re-billed
    assert len(store.read_all()) == len(JOBS)


def test_resume_only_calls_the_jobs_that_are_missing(store):
    client = FakeClient()
    drive(store, client)

    store.path_for("defender", "C3", "t02", 0).unlink()
    drive(store, client)

    assert client.calls == len(JOBS) + 1


def test_truncated_record_raises_legibly(store):
    path = store.write(RECORD)
    path.write_text(json.dumps(RECORD.output)[:20], encoding="utf-8")

    # Pinned behaviour: raise, do not skip. A skipped record under-reports
    # spend, which is what the pilot gate exists to catch.
    with pytest.raises(ValueError, match=r"not a readable run record"):
        store.read_all()


def test_record_missing_a_usage_field_raises_legibly(store):
    path = store.write(RECORD)
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["usage"]["cache_read_input_tokens"]
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match=r"not a readable run record"):
        store.read_all()


def test_read_readable_returns_the_good_records_and_the_bad_paths(store):
    store.write(RECORD)
    bad = store.write(replace(RECORD, sample=1))
    bad.write_text("{ truncated", encoding="utf-8")

    records, unreadable = store.read_readable()

    # The summariser can still produce a floor, and still has to name the file.
    assert records == (RECORD,)
    assert unreadable == (bad,)


def test_crash_between_temp_and_rename_leaves_no_record(store, monkeypatch):
    def boom(src, dst):
        raise OSError("killed mid-write")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.write(RECORD)

    # The half-written temp file is not a record, and read_all must not see it.
    assert not store.exists("defender", "C1", "t01", 0)
    assert store.read_all() == ()
    assert store.read_readable() == ((), ())


def test_a_later_write_sweeps_the_orphan_temp_of_a_crashed_one(store, monkeypatch):
    def boom(src, dst):
        raise OSError("killed mid-write")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.write(RECORD)
    assert len(list(store.path_for("defender", "C1", "t01", 0).parent.glob("*.tmp"))) == 1

    monkeypatch.undo()
    path = store.write(RECORD)

    assert list(path.parent.glob("*.tmp")) == []
    assert store.read_all() == (RECORD,)


def test_rewriting_a_record_replaces_it(store):
    store.write(RECORD)
    store.write(replace(RECORD, output="rerun"))

    assert store.read_all() == (replace(RECORD, output="rerun"),)


def test_path_for_is_stable_and_distinct_across_every_stage_condition(store):
    paths = {
        (stage, condition): store.path_for(stage, condition, "t01", 0)
        for stage in STAGES
        for condition in CONDITIONS
    }

    assert len(set(paths.values())) == len(paths)
    for (stage, condition), path in paths.items():
        assert path == store.path_for(stage, condition, "t01", 0)
        assert path.is_relative_to(store.root)
        assert path.suffix == ".json"


def test_path_for_survives_filesystem_hostile_names(store):
    path = store.write(
        replace(RECORD, condition="", transcript="corpus/t 01:draft", sample=12)
    )

    assert store.read_all()[0].transcript == "corpus/t 01:draft"
    assert not set(path.relative_to(store.root).parts) & {"", ".", ".."}
    for part in path.relative_to(store.root).parts:
        assert not set(part) & set('<>:"/\\|?*')


def test_dot_components_never_reach_the_path(store):
    for hostile in ("..", ".", "", "/", "../.."):
        parts = store.path_for("defender", hostile, hostile, 0).relative_to(store.root)
        assert not set(parts.parts) & {"", ".", ".."}


def test_samples_sort_in_order(store):
    # Weak on Windows — NTFS hands back name-ordered entries, so this would
    # still pass with `sorted()` removed from `read_all`. Not a guard.
    for sample in (0, 2, 10):
        store.write(replace(RECORD, sample=sample))

    assert [r.sample for r in store.read_all()] == [0, 2, 10]


# ------------------------------------------------------------------- failed()


def test_failed_reads_the_shape_every_stage_writes():
    """The defender, the attacker and the control arm all write `{"failed": ...}`.
    One predicate, because it now gates a *denominator* rather than merely
    skipping an attack: `aggregate` drops a failed defender record out of #13's
    note set entirely."""
    assert failed(replace(RECORD, output=json.dumps({"failed": "refusal"})))
    assert not failed(replace(RECORD, output="### What changed\nA real note.\n"))


def test_failed_is_the_only_copy_of_itself():
    """It used to be duplicated verbatim in two modules, with `aggregate`
    importing one and `pilot` calling the other, and a comment asserting they
    were one concept while nothing enforced it."""
    assert attacker.failed is failed
    assert defender.failed is failed


@pytest.mark.parametrize("output", ["null", "[]", '"failed"', "3", "true"])
def test_a_json_document_that_is_not_an_object_is_not_a_failure(output):
    """`json.loads` returns whatever the document says. A bare `null` makes
    `"failed" in data` raise `TypeError`, and the legal JSON *string* `"failed"`
    would answer True — silently deleting a real note from every denominator."""
    assert not failed(replace(RECORD, output=output))
