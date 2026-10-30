# An extra history-box entry that opens and lies poisons older epochs for good
> Summary: `open_histories` takes the first live entry of a history key that opens, stores every earlier secret it lists as trusted and adds them to the epoch's supersedes; later genuine boxes or history boxes never replace a held secret. A reader with an invite (via a grant's history boxes) or any writer (via its rotation's history box) can list garbage for older epochs, and every later joiner gets and re-spreads it.
> Tags: security, keys, engine

Severity: medium (a reader can make history unreadable for future members; nothing repairs it).

Scenario: R has `{read, invite: read}` on G and holds G's current read epoch E. R makes a valid invite grant whose `/secrets` puts a second entry at history key `(read, E)`, encrypted under E's secret, listing `(E-1, garbage)`. Grant checks only the key's role (core/engine/src/apply/validity.rs:614). `open_histories` (core/keys/src/open.rs:118-160) opens it (possibly first, by stamp), marks the key done, `set_secret`s the garbage (open.rs:150) and records the supersede (open.rs:143); `ingest_with` (open.rs:184) and open.rs:150 never overwrite a held secret. The garbage counts as established-held and goes into the node's own later history boxes (`produce.rs` via `held_established`).

Spec: spec/crypto.md §4 a history box carries the rotator's earlier established secrets and a grant writes it "again unchanged".

Fix direction: check each history-derived secret against that epoch's keyset when its `/keys` write is held (KEM/delete key derivation); try every live entry, not first-opener; treat entries not written by the epoch's own rotation commit as reading-only candidates; let a genuine applied box replace a held secret that fails the keyset check.
