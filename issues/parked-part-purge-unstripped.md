# A purged part of a parked commit stays whole
> Summary: `strip_purged` skips a waiting part it cannot decode (unknown version or encoding), so a purge leaves its values in the pending store; spec/versioning.md §2 says purges still apply and spec/commits.md §5 says what cannot be stripped goes.
> Tags: engine, security

core/engine/src/retention/pending.rs `strip_purged`: `verify_part` failing with a parked error (`UnknownVersion`, `UnknownEncoding`) hits `_ => continue`: the part is neither stripped nor removed. Only a missing page (`is_missing_page`) makes it go whole.

Spec: spec/versioning.md §2, a body the node could not join: "purge requests, expiry and absolute keep-at-most bounds still apply"; spec/commits.md §5: "With a page of it not held it cannot be stripped: it goes at once". Expiry already goes whole (`pending_drops`, test `parts::parked_part_goes_at_its_expiry_spec_commits_5`). held-model gives a purged parked body `MustDrop(Gone)` (AMBIGUITIES.md 39).

Fix: treat a parked decode error like a missing page (remove the part, flag the aspect, `pended`). Repro: a parked commit (an aspect with an unknown encoding, as `parts.rs` builds for the expiry test) on an aspect a later applied purge request by an admin names; after the request applies, `Engine::pending_value_past_end` (or the stored copy) still holds the part. Found by code reading (held-model-2 adapter review), not yet by a test.
