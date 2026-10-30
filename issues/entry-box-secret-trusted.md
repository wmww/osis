# An entry-box read secret is stored as trusted under an epoch the box names
> Summary: `learn_read_secret` (recovery or link key opening by static entry) stores the secret with `set_secret`, not as a reading-only candidate, under the epoch the entry box claims; a removed admin that still controls a server's head can register a step with its own secret labelled as the new epoch, and the restored or redeeming device then wraps its writes under the attacker's secret, the genuine box never replacing it.
> Tags: security, engine, keys

Severity: medium (needs the removed-admin window before the remover re-registers, which spec/sync.md §2 accepts, but the result is a lasting confidentiality loss).

Scenario: admin A' is removed from P. Before the remover re-registers at server S, A' (still holding the head's admin key) learns the new read epoch ID E_new (the rotation commit is wrapped under the old read epoch) and registers a child step whose sync key derives from a secret S' it chose, with an entry box for the recovery key carrying (E_new, S'). A device restoring from the card opens by static entry: `static_secret` (core/node/src/sync/open.rs:342-363) checks only that S' derives the head's sync key; `learn_read_secret` (core/engine/src/apply/keys.rs:509-517, doc comment says "kept for reading" but calls `set_secret`) stores it trusted. The genuine box at E_new is later skipped (core/keys/src/open.rs:184: only set when none held); `newest_held` returns S' and `wrap_epoch` (core/keys/src/wrap.rs:20) wraps the device's writes under it: A' reads them, honest members cannot.

Spec: spec/crypto.md §4 "A node encrypts under established epochs only"; a secret from an unverified source is a reading-only candidate.

Fix direction: store entry-box secrets with `set_reading_secret` and prune them by the keyset check; on an applied valid box, replace a held secret that does not derive the epoch's published keyset.
