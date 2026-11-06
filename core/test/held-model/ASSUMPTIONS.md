# held-model: scope cuts
> Summary: What held-model leaves out or simplifies, so a mismatch against the engine in these areas is not a finding.

**Model shape**
- One node's view, no network: no sync scope (every thing counts as synced), labels, hosts, must-hold, lasting headers, header-only blobs, delete keys, uploads or carrier writing. A carrier is reported as needed (`DropWhy::AtMost { carrier }`), never written.
- A body is one part (one delta), not a blob of a commit's deltas per reader section and retention class.
- `Body::Dropped` does not record why (keep bounds or covered), so a covering snapshot turning invalid does not bring the body back as never received, and a dropped-valid snapshot taking back what it gave counts every dropped delta as dropped otherwise (spec/permissions.md §5.2). No suspect flags.
- A leftover holding no value of its own is terminal (AMBIGUITIES.md 9): a purge's fall makes its body never received, a lost read access (Keep copies) is not modeled.
- Role-class bodies are always kept.
- Commit IDs are unique in the input; duplicates and copies of a delta (spec/commits.md §4 Copies) are not modeled. Arrival order is not modeled beyond `Body::Dropped` (its commit applied) and `Held::dropped_valid`: "a commit such a part applied before T stays applied" holds only through a dropped part, and late parts of applied commits are parts held from the start.
- A parked part a purge drops (`Gone`) still counts as held for its commit's pending until `act` makes it missing (its judgment needs the applied set). No bad-by-itself deltas, so no bad-input blobs.

**Clock and stamps**
- Deaths are dated at the earliest held superseder (no arrival order): an engine dating at the first superseder it held may date later, never earlier (AMBIGUITIES.md 5).
- `ts = wall_ms * 2^16 + logical`; `now` is the node's corrected wall clock. Commit-form dots only: no sessions, frontier tables or `Absorbed`.
- Unknown encodings exist only as `Body::Parked` (a part as a whole); no links, pages, chunks or list-by-link waits.

**Permissions**
- Holders and first admins are actors (nodes, things); effective roles are widest paths over alive edges and record edges. No `MAX_CHAIN_DEPTH`, keys, secrets, rotation, certificates, `tied` edges, `keyset`, retain or erase (Keep copies), `LOST_HEARD_WAIT_MS`, or role-class aspects other than `roles.0`.
- No `created.0` parts: `things` are the known records, from wherever they came; a commit carrying a thing's record applies no differently.
- Edge as restored: the join over the written edge only; a demoter's kept standing is not modeled beyond "R never demotes its own author" (its author is never audited by it).
- `required.0^`: one entry per AK name or the empty prefix (AKs have no longer prefixes); no `retain`, `MAX_REQUIRED_ENTRIES`, or dropping without a right (spec/permissions.md §6 Without a right: it needs arrival order).

**CRDT**
- Register at the aspect root; a map of keys to registers (an entry's value is a single register; no key-erased records, `put_new` or nested composites); text with insert, delete and undelete (no moves, slots or embedding). No bags, sets, structs, enums or lists.
- Snapshots are honest: their copies equal the deltas' (a differing copy joins by the copy order, spec/permissions.md §5.2, spec/crdt.md §4.1; never generated here). Snapshot retention is taken as given, not recomputed from its writes' own deltas.
- Undo (`undo::undo`): register, map and text rules, Absent before at the aspect root only; no creation undo (`created.0`), ephemeral undo, moves or position writes; an undo commit is one commit (the generator undoes one-part commits, so one expiry).
- No ephemeral data, no bad-input rules (a write of the wrong kind for its aspect is ignored).
- An unjoinable (parked) body ignores absolute keep-at-most bounds.
