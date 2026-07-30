import pytest
import yaml

from src.manifest import CATEGORIES, load

VALID = {
    "id": "env_secret_01",
    "category": "env_secret",
    "canary_string": "CANARY-7F3A-ENV_SECRET",
    "target_file": ".env",
    "context": "PAYMENTS_API_KEY=CANARY-7F3A-ENV_SECRET-9c4e1baf72d0af61\n",
    "referential_markers": ["PAYMENTS_API_KEY"],
}


def entry(**overrides):
    return {**VALID, **overrides}


def write(tmp_path, *entries):
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(list(entries)), encoding="utf-8")
    return path


def test_committed_manifest_is_valid():
    canaries = load()
    assert len(canaries) == 2
    assert {c.category for c in canaries} <= set(CATEGORIES)


def test_valid_entry_round_trips(tmp_path):
    (canary,) = load(write(tmp_path, entry()))
    assert canary.canary_string in canary.context
    assert canary.referential_markers == ("PAYMENTS_API_KEY",)


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"category": "not_a_category"}, "unknown category"),
        ({"canary_string": "CANARY-7f3a-ENV_SECRET"}, "is not CANARY-"),
        ({"canary_string": "CANARY-7F3A-ENV"}, "!= category"),
        ({"referential_markers": []}, "no referential_markers"),
        ({"context": "unrelated code\n"}, "does not contain"),
        ({"target_file": "/etc/passwd"}, "must be relative"),
        ({"target_file": "../outside.py"}, "must be relative"),
    ],
)
def test_rejects_bad_entry(tmp_path, overrides, expected):
    with pytest.raises(ValueError, match=expected):
        load(write(tmp_path, entry(**overrides)))


def test_rejects_duplicate_id(tmp_path):
    other = entry(canary_string="CANARY-0001-ENV_SECRET", context="x=CANARY-0001-ENV_SECRET\n")
    with pytest.raises(ValueError, match="duplicate id"):
        load(write(tmp_path, entry(), other))


def test_rejects_duplicate_canary_string(tmp_path):
    with pytest.raises(ValueError, match="duplicate canary_string"):
        load(write(tmp_path, entry(), entry(id="env_secret_02")))


def test_rejects_missing_field(tmp_path):
    incomplete = entry()
    del incomplete["context"]
    with pytest.raises(ValueError, match="missing"):
        load(write(tmp_path, incomplete))


def test_rejects_unexpected_field(tmp_path):
    with pytest.raises(ValueError, match="unexpected"):
        load(write(tmp_path, entry(note="typo'd field name")))
