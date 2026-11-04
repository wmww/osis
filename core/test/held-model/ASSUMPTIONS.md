# held-model: scope cuts
> Summary: What held-model leaves out or simplifies, so a mismatch against the engine in these areas is not a finding.

**Model shape**
- One node's view, no network: no sync scope (every thing counts as synced), labels, hosts, must-hold, lasting headers, header-only blobs, delete keys, uploads or carrier writing. A carrier is reported as needed (`DropWhy::AtMost { carrier }`), never written.
- A body is one part (one delta), not a blob of a commit's deltas per reader section and retention class.
- `Body::Dropped` does not record why (keep bounds or covered), so a covering snapshot turning invalid does not bring the body back as never received. No suspect flags.
- Leftovers are terminal (AMBIGUITIES.md 9). Role-class bodies are always kept (no roster snapshots to replace them).
- Commit IDs are unique in the input; duplicates and copies of a delta (spec/commits.md §4 Copies) are not modeled.

**Clock and stamps**
- `ts = wall_ms * 2^16 + logical`; `now` is the node's corrected wall clock. Commit-form dots only: no sessions, frontier tables or `Absorbed`.
- Parking is the only clock wait. Unknown encodings, links, pages and chunks do not exist.

**Permissions**
- Things are owned by nodes; holders are nodes. No actors as holders, owner chains above one link, ownerless things, invites, `until`, self-removals, roster snapshots or tenures, acting-for, keys, secrets, rotation or certificates.
- No `created.0`: every thing's record is known, so no thing waits.
- No `required.0^`.

**CRDT**
- Register at the aspect root; a map of keys to registers (an entry's value is a single register; no key-erased records, `put_new` or nested composites); text with insert and delete (no moves, undelete, slots or embedding). No bags, sets, structs, enums or lists.
- Snapshots are honest: no misstatement handling (spec/permissions.md §5.2). Snapshot retention is taken as given, not recomputed from its writes' own deltas.
- No undo, no ephemeral data, no bad-input rules (a write of the wrong kind for its aspect is ignored).

**Consequence**: a waiting part past its expiry cannot occur (an expired missing part counts as held and parking ends before any expiry), so that rule (spec/commits.md §5) is not exercised.
