# held-model: scope cuts
> Summary: What held-model leaves out or simplifies, so a mismatch against the engine in these areas is not a finding.

**Model shape**
- One node's view, no network: no sync scope (every thing counts as synced), labels, hosts, must-hold, lasting headers, header-only blobs, delete keys, uploads or carrier writing. A carrier is reported as needed (`DropWhy::AtMost { carrier }`), never written.
- A body is one part (one delta), not a blob of a commit's deltas per reader section and retention class.
- `Body::Dropped` does not record why (keep bounds or covered), so a covering snapshot turning invalid does not bring the body back as never received. No suspect flags.
- A leftover holding no value of its own is terminal (AMBIGUITIES.md 9): a purge's fall makes its body never received, a lost read access (Keep copies) is not modeled.
- Role-class bodies are always kept: a roster snapshot replacing them (their keep-at-least `ROLE_KEEP` after it) drops none.
- Commit IDs are unique in the input; duplicates and copies of a delta (spec/commits.md §4 Copies) are not modeled. Arrival order is not modeled: "a commit such a part applied before T stays applied" and late parts of applied commits do not exist.

**Clock and stamps**
- Deaths are dated at the earliest held superseder (no arrival order): an engine dating at the first superseder it held may date later, never earlier (AMBIGUITIES.md 5).
- `ts = wall_ms * 2^16 + logical`; `now` is the node's corrected wall clock. Commit-form dots only: no sessions, frontier tables or `Absorbed`.
- Unknown encodings exist only as `Body::Parked` (a part as a whole); no links, pages, chunks, linked frontiers or list-by-link waits.

**Permissions**
- Holders and owners are actors (nodes, things); effective roles are widest paths over alive edges and owner links. No `MAX_OWNER_DEPTH`, keys, secrets, rotation, certificates, `tied` edges, `keyset`, keep or erase (Keep copies), `LOST_HEARD_WAIT_MS`, or role-class aspects other than `roles.0` and `tenures.0`.
- No `created.0` parts: `things` are the known records, from wherever they came; a commit carrying a thing's record applies no differently.
- Roster snapshots: one thing per snapshot, no reset-only deltas, no linked frontiers or `MAX_LINKED_FRONTIERS`; a snapshot taking no part in the walk only for naming a holder twice. A roster's pre-start values apply without an authority check (AMBIGUITIES.md 33).
- Edge as restored: the join over the written edge only; a demoter's kept standing is not modeled beyond "R never demotes its own author" (its author is never audited by it).
- `required.0^`: one entry per AK name or the empty prefix (AKs have no longer prefixes); no `keep`, `MAX_REQUIRED_ENTRIES`, or dropping without a right (spec/permissions.md §7 Without a right: it needs arrival order).

**CRDT**
- Register at the aspect root; a map of keys to registers (an entry's value is a single register; no key-erased records, `put_new` or nested composites); text with insert, delete and undelete (no moves, slots or embedding). No bags, sets, structs, enums or lists.
- Snapshots are honest: no misstatement handling (spec/permissions.md §5.2). Snapshot retention is taken as given, not recomputed from its writes' own deltas.
- Undo (`undo::undo`): register, map and text rules, Absent before at the aspect root only; no creation undo (`created.0`), ephemeral undo, moves or position writes; an undo commit is one commit (the generator undoes one-part commits, so one expiry).
- No ephemeral data, no bad-input rules (a write of the wrong kind for its aspect is ignored).
- An unjoinable (parked) body ignores absolute keep-at-most bounds.
