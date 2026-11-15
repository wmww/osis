# The secrets memo's amend keeps boxes a fresh decode drops
> Summary: re-ingesting a held grant after a self-removal amends `secrets: decode` (`apply/atomic.rs` `secrets_patch`) to a value holding boxes a fresh `secrets_decoded` no longer gives; a debug build panics ("a read no stamp covers"), a release build would serve the stale secrets.
> Priority: normal
> Tags: engine, security

- Repro: make `held.rs` take an applied inbox blob again (in `judge`, drop the `was`-act shortcut so `take_inbox` runs at every move), then `cargo test -p osis-sync --test it flows::a_self_removal_drops_its_secrets_once_held_elsewhere_spec_sync_status_2` (also `siblings::a_siblings_self_removal_waits_and_drops_at_both_siblings_spec_perm_3`, `convergence::histories_converge` seed 1). The kept value holds the thing's symmetric boxes for the removed holder at the new epoch; a fresh decode holds only the sealed ones.
- The inbox module takes a blob whose commit applied once, so main no longer re-ingests that way; any other route re-ingesting a held commit with a `secrets.0` delta after a self-removal would hit it. Likely cause: `secrets_patch` mirrors the joined state's live entries, while `secrets_decoded` reads something the self-removal changed (dropped parts or kept secrets) that the patch does not see.
- Fix: make the patch read what the decode reads (or decline to patch then), with a test ingesting a held grant again after a self-removal.
