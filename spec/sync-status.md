# Sync: status
> Summary: Area 7: sources and being caught up, when a node's own commit is held elsewhere, and what `status`, `wait_synced` and history completeness say per sync ID.

**Principle:** status says only what is true now, per sync ID, of the sources connected now. Nothing is "synced" with nobody connected, and no word of a peer counts until its stream showed it.

## 1. Sources and caught up
- The **sources** of S at a node: the peers with S open on a connection up now (spec/sync-opens.md §4). A granted peer that has not taken its grant, or a node that refuses S, is no source.
- A source is **caught up** once this node applied its stream to the end (spec/sync-streams.md §4) and the source reported (Applied) every message of S served to it. A source **lacks** an entry only for what it would pull (stamped for its head, or a deposit it was offered); a full or refusing source (spec/sync-streams.md §4 Full, Refused) is named, counts as lacking what it lacks, and is not waited on.
- S is **heard out** at a node when every source is caught up. With no source S is **unconnected**, one state, never synced.
- Readers are counted by identity (the accounts proven, spec/sync-opens.md §2), never by connection.

## 2. Held elsewhere
- A commit a node made, or a self-removal by its account, itself or a key actor it holds (spec/permissions.md §2) that it holds, is **held elsewhere** when each sync ID it syncs of the things the commit touches holds the parts of it that sync ID's actor reads that it must hold (spec/sync-judgement.md §2) in an entry at a source, or covered by a snapshot there, by the source's stream (`known`, spec/sync-judgement.md §3): present there, not counting as lacking there (spec/sync-ids.md §6 Wraps), or reported by a source that reads S at a position at or past where this node's log first held the entry (for a member being ended, the entry first logged at or below its `until`). A node's own other nodes never count for its self-removal (they leave by the same commit).
- A node records each such report on a commit not yet held elsewhere, durably, kept while the entry is. Copies of it elsewhere (certificate copies, inbox blobs) do not wait for it (spec/commits.md §4).

## 3. Status and waits
- `status` per sync ID: unconnected, or its sources each with caught up, lacking (with counts), full, refusing, or stranded; and per node, idle when no request, fill or Hello is outstanding on any connection (a dialed session waiting for the peer's Hello is not idle).
- A node keeping S unread reports S like any sync ID (its sources, its head, full, stranded).
- **Stranded** (spec/permissions.md §4): a node holding S that has no credential of a source's head reports itself stranded there and sends its stranded notice again when its holder's current keys move.
- `wait_synced(S)` ends when S is heard out and each of this node's own commits under S is held elsewhere; a writer's wait ends on a source keeping S unread reporting it applied the writer's entries. It never ends while S is unconnected.
- **History complete** for a thing: a pass that heard out every sync ID carrying it (spec/permissions.md §3 complete pass).
- `set_role` writes at once; an app that needs the change seen first waits with `wait_synced`.
- A wait on a thing that never arrives, or was left and forgotten, runs to its timeout; status names the thing unknown meanwhile.
- `SETTLE_MS` (spec/wire.md §2) is the only wait on others' liveness, and only for rotation decisions.
