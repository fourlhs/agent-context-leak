import dataclasses

import pytest
import yaml

from src.manifest import CATEGORIES, DEFAULT_SLOT, TAIL_REQUIRED_CATEGORIES, Canary, load

VALID = {
    "id": "env_secret_01",
    "category": "env_secret",
    "canary_string": "CANARY-7F3A-ENV_SECRET",
    "entropy_tail": "9c4e1baf72d0af61",
    "target_file": ".env",
    "context": "PAYMENTS_API_KEY=CANARY-7F3A-ENV_SECRET-9c4e1baf72d0af61\n",
    "referential_markers": ["PAYMENTS_API_KEY"],
}

TAILLESS = {
    "id": "indiscreet_comment_01",
    "category": "indiscreet_comment",
    "canary_string": "CANARY-B2E9-INDISCREET_COMMENT",
    "entropy_tail": "",
    "target_file": "db.py",
    "context": "# FIXME(CANARY-B2E9-INDISCREET_COMMENT): still open\n",
    "referential_markers": ["hammers the read replica"],
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
        ({"slot": "Refund Headers"}, "must be lowercase"),
    ],
)
def test_rejects_bad_entry(tmp_path, overrides, expected):
    with pytest.raises(ValueError, match=expected):
        load(write(tmp_path, entry(**overrides)))


def test_slot_is_optional(tmp_path):
    """#3 authors ten entries against this schema, so a second required field
    would mean writing them all twice."""
    (defaulted,) = load(write(tmp_path, entry()))
    assert defaulted.slot == DEFAULT_SLOT
    (named,) = load(write(tmp_path, entry(slot="refund_headers")))
    assert named.slot == "refund_headers"


def test_planted_value_appends_the_entropy_tail(tmp_path):
    (canary,) = load(write(tmp_path, entry()))
    assert canary.planted_value == "CANARY-7F3A-ENV_SECRET-9c4e1baf72d0af61"
    assert canary.planted_value in canary.context


def test_tailless_canary_planted_value_is_the_label(tmp_path):
    (canary,) = load(write(tmp_path, TAILLESS))
    assert canary.planted_value == canary.canary_string


def test_rejects_context_missing_the_tail(tmp_path):
    """The check that would have caught #29 at the manifest layer."""
    label_only = entry(context="PAYMENTS_API_KEY=CANARY-7F3A-ENV_SECRET\n")
    with pytest.raises(ValueError, match="does not contain"):
        load(write(tmp_path, label_only))


@pytest.mark.parametrize(
    "tail",
    [
        "9c4e",  # below the 8-hex floor
        "9C4E1BAF",  # uppercase
        "nothexxx",  # right length, not hex
        None,  # a bare `entropy_tail:` in YAML
        12345678,  # an all-digit tail written unquoted
    ],
)
def test_rejects_malformed_entropy_tail(tmp_path, tail):
    with pytest.raises(ValueError, match="entropy_tail"):
        load(write(tmp_path, entry(entropy_tail=tail)))


def test_tail_required_categories_are_pinned():
    """Parametrising over the constant would not notice it shrinking. #3 authors
    ten canaries against it; losing a category here ships a whole secret-shaped
    one with planted_value == canary_string."""
    assert set(TAIL_REQUIRED_CATEGORIES) == {"env_secret", "hardcoded_credential"}
    assert set(TAIL_REQUIRED_CATEGORIES) <= set(CATEGORIES)


def test_entropy_tail_has_no_default():
    """Breaking loudly at every construction site is the point: a default would
    let existing callers silently declare 'no tail'."""
    (field,) = [f for f in dataclasses.fields(Canary) if f.name == "entropy_tail"]
    assert field.default is dataclasses.MISSING
    assert field.default_factory is dataclasses.MISSING
    with pytest.raises(TypeError):
        Canary(
            id="x",
            category="env_secret",
            canary_string="CANARY-0001-ENV_SECRET",
            target_file=".env",
            context="",
            referential_markers=(),
        )


def test_planted_value_raises_rather_than_degrading_to_the_label():
    """A non-str tail must not silently reinstate #29 for construction sites
    that bypass validate()."""
    broken = Canary(
        id="x",
        category="env_secret",
        canary_string="CANARY-0001-ENV_SECRET",
        entropy_tail=None,
        target_file=".env",
        context="",
        referential_markers=(),
    )
    with pytest.raises(TypeError, match="entropy_tail"):
        broken.planted_value


def test_rejects_duplicate_entropy_tail(tmp_path):
    """The tail is a needle on its own, so a shared one cross-triggers."""
    other = entry(
        id="env_secret_02",
        canary_string="CANARY-0001-ENV_SECRET",
        context="x=CANARY-0001-ENV_SECRET-9c4e1baf72d0af61\n",
    )
    with pytest.raises(ValueError, match="duplicate entropy_tail"):
        load(write(tmp_path, entry(), other))


@pytest.mark.parametrize("category", TAIL_REQUIRED_CATEGORIES)
def test_secret_shaped_categories_require_a_tail(tmp_path, category):
    label = f"CANARY-0002-{category.upper()}"
    bad = entry(
        category=category,
        canary_string=label,
        entropy_tail="",
        context=f"KEY={label}\n",
    )
    with pytest.raises(ValueError, match="entropy target"):
        load(write(tmp_path, bad))


def test_committed_manifest_has_a_measurable_label_value_gap():
    """Non-degeneracy: with no tails anywhere, verbatim_label and verbatim_value
    are the same column and the two-column measurement has silently collapsed."""
    assert any(c.planted_value != c.canary_string for c in load())


def test_rejects_duplicate_id(tmp_path):
    other = entry(
        canary_string="CANARY-0001-ENV_SECRET",
        entropy_tail="00112233445566aa",
        context="x=CANARY-0001-ENV_SECRET-00112233445566aa\n",
    )
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
