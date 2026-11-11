# held-model: scope cuts
> Summary: What held-model leaves out or simplifies, so a mismatch against the engine in these areas is not a finding.

**Model shape**
- One node's view, no network: no sync scope (every thing counts as synced), labels, hosts, must-hold, lasting headers, header-only blobs, delete keys or uploads. The covering snapshot a writer owes is reported (`Outcome::owed`) and written only by the caller (`cover`); nothing fetches a body again, the caller does from what `Outcome::uncovered` and `Fate::NeverReceived` name.
- A body is one part (one delta), not a blob of a commit's deltas per reader section and retention class.
- No suspect flags: a body whose cover fell is never received at once.
- `history()` is the set of replaced writes of kept bodies (stamp and carrying commit), not an API shape; what it shows for a write replaced several times, or exposes of a snapshot's copies, is not modeled.
- A local drop as covered needs no right of the node's own (the snapshot's commit holds it): the spec's "the node itself holds it now" binds compaction's host deletion, not modeled.
- A leftover holding no value of its own is terminal (AMBIGUITIES.md 9): a purge's fall makes its body never received, a lost read access (Keep copies) is not modeled.
- Role-class bodies are always kept.
- Commit IDs are unique in the input; duplicates and copies of a delta (spec/commits.md §4 Copies) are not modeled. Arrival order is not modeled beyond `Body::Dropped` (its commit applied) and `Held::dropped_valid`: "a commit such a part applied before T stays applied" holds only through a dropped part, and late parts of applied commits are parts held from the start.
- A parked part a purge drops (`Gone`) still counts as held for its commit's pending until `act` makes it missing (its judgment needs the applied set). No bad-by-itself deltas, so no bad-input blobs.

**Clock and stamps**
- `ts = wall_ms * 2^16 + logical`; `now` is the node's wall clock. Commit-form dots only: no sessions, frontier tables or `Absorbed`.
- Unknown encodings exist only as `Body::Parked` (a part as a whole); no links, pages, chunks or list-by-link waits.

**Permissions**
- Holders and first admins are actors (nodes, things); effective roles are widest paths over alive edges and record edges. No `MAX_CHAIN_DEPTH`, keys, secrets, rotation, certificates, `tied` edges, `keyset`, retain or erase (Keep copies), `LOST_HEARD_WAIT_MS`, or role-class aspects other than `roles.0`.
- Records as writes and ending are modeled from notes/expiry-creation-design.md §3 (spec/ follows with steps 6 and 7): a thing is unknown or ended where spec/commits.md §4 still says a part waits.
- A `created.0` part is one `Delta::Created` write; a second minting of a thing is never generated. `Held::records` are raw records from wherever they came.
- Edge as restored: the join over the written edge only; a demoter's kept standing is not modeled beyond "R never demotes its own author" (its author is never audited by it).
- `required^.0`: one entry per AK name and the default; no `retain` or `MAX_REQUIRED_ENTRIES`.

**CRDT** (values are crdt-model's: what it leaves out is left out here too)
- Snapshots are honest: their copies equal the deltas' (a differing copy joins by the copy order, spec/permissions.md §5.2, spec/crdt.md §4.1; never generated here). Snapshot retention is taken as given, not recomputed from its writes' own deltas (`snapshot_retention` is what the generator and `cover` use).
- A snapshot body is taken whole into the state: un-merge removes invalid deltas' writes from content bodies only, keeping the records the valid snapshots hold (spec/crdt.md §4.6).
- Undo (`undo::undo`): each aspect written to read as without the undone commit (its writes gone from every body), on the generator's aspects; no check that the inverse restores only kept content (spec/crdt.md §4.6, spec/commits.md §7), no creation undo (`undo::undo` refuses a creation), ephemeral undo or redo beyond an undo of the undo; an undo commit is one commit (the generator undoes one-part commits, so one expiry).
- No ephemeral data, no bad-input rules. Signals: a signal part keeping no history or in a snapshot is bad input (spec/commits.md §2), never generated; nor is one holding anything but one root register write (its writer refuses it); the generator never undoes a signal write (it undoes one-part commits, and a signal's has nothing to write back, spec/crdt.md §4.6).

**Signal edits** (`edits::listing`, notes/signal-edits-design.md)
- A node's own invalid parts are not in the listing (spec/commits.md §7: marked, read as themselves), so the fold reads only valid parts and is alike at every node.
- A part listed needs its body held or a purge. A header-only original is not distinguished from one not held.
- A purged part's listing is counted from the request `Outcome::purged` names (the lowest ID of those that do).
- `final`, an edit's expiry bound under a required rule, and a purge request reaching only deltas expiring by its commit's `expires`: not modeled.
