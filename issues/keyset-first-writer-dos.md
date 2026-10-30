# A writer's bogus keyset at an existing epoch drops the genuine secret on late joiners
> Summary: `RoleEpochs::set_keyset` keeps the first keyset recorded for an epoch, from any applied valid `/keys` write or the `/keys` state; a writer can re-publish the current read or write epoch with junk KEM and delete keys, and a node that records that keyset first (a late joiner after compaction, or one that applies a commit whose parents skip the rotation) refuses the genuine box and drops the genuine secret for good. Fix direction: self-certifying epoch nonces.
> Tags: security, keys, engine

Severity: medium (needs a malicious writer; permanent loss of reading on the affected nodes, divergent across nodes).

Scenario (reproduced in review of key-trust): A owns t, W writes, M reads. A removes M (rotation to read epoch E). W writes `/keys` with read keyset `{epoch: E, kem_key, delete_key}` taken from another keyset (valid: a writer may write the read keyset, `rotation_required`); its LWW write wins in the state. A compacts `/secrets` and `/keys`, writes a roster snapshot and grants D read; D gets everything but A's rotation and W's commit. D's `observe_state("/keys")` records W's keyset for E first, so `set_box_secret` refuses D's genuine box at E: D holds no secret of E (A's keyset of E is genuine, D's is W's). Same without compaction when W's commit names parents without E's rotation and reaches a node first; and a commit later found invalid keeps its keyset (records are never undone).

Before key-trust a keyset only pruned reading-only candidates, so this is new; a writer could already poison history boxes (first-opener-wins), which key-trust fixed for invite holders.

Related, pre-existing: `apply::keys::invalidated` unsets `applied` (and `history`) of every epoch whose keyset the invalid commit set, so a writer's re-claim of E that is later invalidated also clears E's genuine rotation record (Chain establishment lost until a rotation or snapshot).

Fix direction: make an epoch name its secret: nonce = first 16 bytes of a KDF of the secret (or of the keyset's KEM key), with n bound in. Every source (box, history entry, entry box, keyset) is then checked alone, in any order: a lying entry is refuted without a recorded keyset, a bogus keyset is refuted by its own epoch, and `EpochInfo::{keyset, history, unverified}` and the "first kept" rules can go. Derived epochs (spec/crypto.md §3) check against the owner's secret; key-actor `Epoch::ZERO` stays fixed.
