# A planted epoch number stops every later rotation
> Summary: `rotate` picks n+1 over every epoch a node has merely observed (`RoleEpochs::max_n`), including epochs named by pending commits from strangers and by invite grants; an epoch with n = i64::MAX makes n+1 overflow (`Error::TooLarge`), so every later rotation of that role fails and removals (which carry their rotation) become impossible. The removed party keeps reading.
> Tags: security, keys, engine, crypto

Severity: high (anyone who can get a membership commit to a node blocks revocation on that actor there, permanently).

Mechanism:
- `osis_keys::produce::rotate` (core/keys/src/produce.rs:236) takes `n = re.max_n()`, the greatest n of any epoch in the map, established or not, then `Epoch::new(n + 1)`, which fails above `i64::MAX` (core/crypto/src/boxes.rs:27).
- Epochs enter the map without any check: `osis_keys::ingest_with` starts with `observe_secrets` on every box and history key (core/keys/src/open.rs `ingest_with`, core/keys/src/aspects.rs `observe_secrets`), also for unchecked sources. `apply::keys::read_pending_boxes` (core/engine/src/apply/keys.rs:420) runs it for every pending membership commit with a `/secrets` part, whatever its author (an unknown author is not even signature-checked yet). `Core::ingest_secrets` (core/engine/src/engine/secrets.rs:153) stores and persists the changed map when the actor is already held. `forget_unchecked` drops reading-only secrets only, never the observed epoch entries.

Scenarios:
1. Stranger: holds the deposit seed of any inbox or label of actor A's admins (contact card, co-reader of any group, departed member). It deposits an inbox blob (or a deposit under A's label) carrying a membership commit by a made-up node with a `/secrets` box keyed `(anyone, read, {n: i64::MAX, ..})` on A. It stays pending forever; A's admin node now fails every read rotation of A. `demote_in` fails, so nobody can be removed from A; `require_covered` fails, so grants, re-seals and labels on A fail too.
2. Invite holder (any link bearer of K): an invite grant may put boxes and history boxes at any epoch (`grantee_boxes_only`, core/engine/src/apply/validity.rs:582 checks member and role only). Applied valid, every node observes the epoch. The sharer can no longer revoke the link or its joiners.
3. Malicious writer: a genuine rotation of read/write at n = i64::MAX is established; admins can never rotate those roles again, so the writer can never be removed.
Also: observed epochs are uncapped (MAX_READING bounds candidates, not epoch entries), so the same plant grows the persisted `k/` record without bound.

Fix direction: take n from established epochs only (spec/crypto.md §4: n+1 of the epochs a rotation supersedes); never record epochs from unchecked sources in the persisted map (keep them beside the reading-only candidates, bounded, dropped with their commit); in the spec, require a rotation's new epoch n to be 1 + max n of what it supersedes (invalid otherwise) and an invite grant's box keys to name epochs only at or below the current ones it can know; reserve headroom (reject n above, say, 2^62).
