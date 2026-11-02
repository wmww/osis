# Epoch establishment by names, frozen coverage: what remains
> Summary: Names establishment and frozen coverage (spec/crypto.md §4) are built on branch keyset-names: an epoch covers only what its rotator named, grants of holder actors carry names. Left: the review, and the open cases in notes/crypto.md (Frozen coverage): later admin path, grant held only as a projection, compaction residue.
> Tags: security, keys, engine, tla

- Rule and invariants: `osis_keys::covers` (by names), `EpochInfo::names_met`, `rotation::departures::{events, names, grant_names_held}`; notes/crypto.md (Frozen coverage).
- Tests: study counterexamples C1 `holder_fork_without_departure_spec_crypto_4`, C1' `holder_forgery_without_departure_spec_crypto_4`, C2 `fork_sibling_reseal_spec_crypto_4`, C3 `grant_names_before_boxing_holder_spec_crypto_4`, `unestablished_successor_history_spec_crypto_4`; still failing: `repro_later_admin_path_forgery_meets_keyset_name_spec_crypto_4` (issues/keyset-name-later-admin-path.md).
- Name completeness is the risk: `thing_names` must stay a superset of `events` (else a rotator never covers what it knows: a livelock). No random harness covers holder actors with forks or grants after rotation; the TLA instances (core/test/tla/rotation) do.
- Orthogonal, unchanged: issues/fork-held-by-non-rotators.md.
