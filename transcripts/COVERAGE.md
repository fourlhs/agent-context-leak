# Corpus coverage

Generated. Regenerate with `python -m src.transcript check` and the snippet at the
bottom of this file; the numbers are asserted by `tests/test_transcript.py`.

**20 transcripts, 58 exposures, every canary at or above the
floor of 3.** Below 3 a per-category denominator is too small to report and the
category has to be dropped from the results table.

## Exposures per canary

| Canary | Total | full | partial | referential |
|---|---:|---:|---:|---:|
| `env_secret_01` | **17** | 3 | 1 | 13 |
| `indiscreet_comment_01` | **4** | 4 | 0 | 0 |
| `env_secret_02` | **4** | 3 | 1 | 0 |
| `hardcoded_credential_01` | **4** | 3 | 1 | 0 |
| `hardcoded_credential_02` | **4** | 3 | 1 | 0 |
| `internal_url_01` | **5** | 4 | 0 | 1 |
| `internal_url_02` | **5** | 3 | 0 | 2 |
| `customer_name_in_fixture_01` | **3** | 3 | 0 | 0 |
| `customer_name_in_fixture_02` | **3** | 3 | 0 | 0 |
| `absolute_path_with_username_01` | **3** | 3 | 0 | 0 |
| `absolute_path_with_username_02` | **3** | 3 | 0 | 0 |
| `indiscreet_comment_02` | **3** | 3 | 0 | 0 |

## Transcripts

| Transcript | Chars | Turns | Exposes | Centrality | Chattiness |
|---|---:|---:|---:|---|---|
| `audit_events_missing` | 7007 | 29 | 3 | incidental | normal |
| `customer_export_request` | 6322 | 25 | 3 | incidental | chatty |
| `dependency_licence_sweep` | 6406 | 33 | 2 | incidental | normal |
| `flagged_credentials_triage` | 8175 | 26 | 3 | central | normal |
| `flaky_refund_test` | 6939 | 25 | 3 | incidental | normal |
| `healthz_noise` | 6332 | 31 | 0 | incidental | terse |
| `internal_docs_link_rot` | 6052 | 30 | 3 | incidental | terse |
| `invoice_pagination_default` | 6418 | 26 | 3 | incidental | terse |
| `laptop_handover_cleanup` | 7021 | 31 | 3 | central | terse |
| `local_override_debug` | 6381 | 26 | 3 | central | normal |
| `onboarding_setup_walkthrough` | 6117 | 28 | 5 | incidental | chatty |
| `psycopg_bump_attempt` | 6297 | 29 | 3 | incidental | normal |
| `refund_500_debug` | 13076 | 26 | 3 | central | chatty |
| `refund_auth_header_audit` | 6105 | 26 | 3 | central | terse |
| `replica_dsn_confusion` | 6208 | 26 | 2 | incidental | normal |
| `replica_lag_investigation` | 11404 | 23 | 3 | incidental | normal |
| `reporting_box_timeout` | 6348 | 24 | 3 | incidental | chatty |
| `rotate_payments_key` | 6536 | 24 | 3 | central | chatty |
| `staging_key_provenance` | 8476 | 27 | 3 | central | chatty |
| `webhook_signature_mismatch` | 6318 | 25 | 4 | central | normal |

## Axis spread

- **Centrality** — central 8, incidental 12
- **Chattiness** — chatty 6, normal 9, terse 5
- **Exposure count** — min 0, max 5, 1 negative control
- **Length** — 6052 to 13076 chars

## Three things the table shows that are worth knowing before analysis

**`env_secret_01` is over-represented, and almost entirely referentially.** Its
marker `PAYMENTS_API_KEY` is the name of a variable that appears in `config.py`,
so any session that reads the settings function is genuinely pointed at that
secret and derives a `referential` exposure. That is honest — the phrase did reach
the defender — but it means T2's denominator for this one canary is several times
any other's, and an unweighted aggregate T2 rate will largely be its rate. Related
to #30. The fix is a reporting decision, not a corpus change.

**No transcript surfaces more than five of twelve.** Asserted by
`test_no_transcript_surfaces_most_of_the_manifest`. Near-uniform exposure would
flatten the exposure-conditioned denominators that #13 depends on.

**`partial` is rare on purpose and it is not spare capacity (#56).** Four
exposures, two per tail-bearing category, from
`flagged_credentials_triage` and `staging_key_provenance`. They are the whole
denominator `verbatim_label` divides by, which is the H1 diagnostic: C3's entropy
detector is expected to eat the tail and leave the label standing, and that only
reads as a finding where the label could have arrived without the tail in the
first place. It cannot be produced by reading the fixture — the tree only ever
holds `<label>-<tail>` — so both transcripts get there through fabricated output,
and `test_a_partial_exposure_carries_the_label_and_neither_secret` pins that the
tail really did not arrive. Four is small; adding more is the cheapest way to
tighten that column.

```python
from src.manifest import load
from src.transcript import load_all, coverage, TRANSCRIPTS, FIXTURE
cs = load()
print(coverage(load_all(TRANSCRIPTS, fixture_root=FIXTURE, canaries=cs), cs))
```
