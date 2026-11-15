# Storage follows synced groups
> Summary: Tess's principle: every byte a node stores is attributable to a synced group, so a user can see which group uses storage, and unsyncing every group drops storage to zero. Plan only (not to build now): audit every durable per-thing, per-peer and per-sync-ID state against "unsync everything gives zero", including purge tombstones, which live only while some synced group carries the purged thing.
> Priority: normal
> Tags: sync, engine, retention

Linked design: issues/refs-graph-lifetime.md (one reference graph for sync, storage and lifetime). The two are likely entangled: under that design "synced group" becomes "the node closure", and the audit's answer for each row is "dropped when it leaves the node closure". Terms below are today's (synced group, closure, sync set: spec/sync-set.md).

## Principle (Tess)
- A node's storage is attributable to its synced groups: for each byte, some group in the sync set's closure is why it is here, and the user can see per synced group what it costs.
- Unsyncing every group drops storage to zero (bar the node's own identity and account records, open question 1).
- **Purge tombstones**: kept, and synced onward to current and new peers, while the node syncs any group carrying the purged thing; dropped when none does. A later re-receipt of the purged content through another group, from a peer that ignored the purge, is accepted.

## Plan
1. List every durable row family and blob the engine, sync and store keep (start from notes/growth.md, which lists growth causes, and the row prefixes `tools/policy.py` checks).
2. For each: what it is keyed by (thing, sync ID, peer, commit, actor), which synced group it is attributable to, and what removes it today.
3. Mark each that survives "unsync everything": the fix is either attribution (key or index it so leaving drops it) or a stated exception.
4. Decide attribution for state shared by several groups (a commit header touching things in two groups, an actor's epochs used by many things): kept while any attributing group is synced, as the tombstone rule says.
5. A test that unsyncs every group and counts store rows and bytes by family (Design principles: test what users can observe; count, not time).

## Candidates (first pass, to verify)
Removed today by unsyncing or the sync ID leaving (spec/sync-set.md §3): a thing's content and its sync ID's store entries (shredded on stopping), per-S members of peer records, `cp/` passes, `changed_at` rows. Kept or unclear:
- **Role-class aspects of an unsynced thing**: Unsyncing keeps `secrets.0` and the other role-class aspects (spec/sync-set.md §3 Unsyncing), and records and `roles.0` edges with them. Removed by nothing once unsynced.
- **Other accounts' chains**: an account's rotations (from sync's certificates or a Prove, `Engine::take_rotations`: what counts plus one dispute's line) and its record stay once no synced group needs the account. Removed by nothing; a Prove's are bounded but not attributable.
- **Node epoch records** (`k/`), derived epochs (`dw/`), keyset epochs, thing lists (`tl/`, `tn/`, `tb/`), grant names in dropped parts: kept with headers or forever (notes/growth.md).
- **Blob rows of forgotten commits** (`bp/`, `sync::bodies`): a commit forgotten as never received (unsyncing, lost access: `apply::unindex_unreceived`) keeps its blobs' "opened or sealed here" rows, keyed by commit and blob only, so `forget_local` can name the blobs to unlog and a copy received again finds its held blob. Nothing removes them when the sync store drops the blob, so they outlive unsyncing for good. Fix: drop them once no entry names the blob (sync tells the engine), or with the forgetting once its blobs are named, after checking what sync does with a not-own entry of such a blob still under a kept sync ID.
- **Commit headers kept after bodies drop** (notes/growth.md row 1), forgotten commits' names (`fn/`).
- **Purge marks**: `pn/`, `p/` lists, lasting tombstones (header-only blobs), destroyed-for-good marks (`td/`): kept for good. Under the principle: kept while a synced group carries the thing, then dropped.
- **Destroyed-thing keeps**: `kd/` secrets and `kl/` sync IDs (issues/destroyed-sync-id-never-left.md), kept records and evidence of destroyed things a held thing needs.
- **Peer records** (`core/store/src/record.rs`): per peer that proved an actor, whatever it shares; bounded by `RECORD_BUDGET` and LRU, not by groups. Their filter rows, `b` charges, `s` stands, `d` deletes seen; tombstones until `TOMBSTONE_LIFETIME`.
- **Refusal and told state**: `T/` (lost by an `until`, gone at the drop), `ra/` and `jc/` (go with the actor's secrets), suspect flags `q/` and reporters' `I/s/` repair rows (issues/suspect-rows-of-gone-things.md: rows of shredded sync IDs stay).
- **Kept unread**: entries a node keeps for sync IDs it holds only a sync secret of, bounded by `caps^.0`; the account's sync records `kept^.0` (entries only added but closed) and `acted^.0` (entries only added, one per thing ever acted on, for good).
- **Inbox**: stamped inbox blobs (expire at `INBOX_LIFETIME`), the opened-payload cache, bearer records (`B/`, go when the link ends).
- **Engine indexes**: reference index rows, lifetime work rows (`lw/`, `lh/`, `lp/`), `node/metas`, `node/edges`, `node/epochs`, sides (admin disputes, for good), history rows (`hr/`, `hf/`), freed links (`fl/`), node log events and deletion events.
- **`retention^.0` bodies**: kept forever per change (notes/growth.md row 4).
- **Kept copies** of a removal saying retain (`K/`): the user's choice, dropped by `drop_retained_copy`; open question 2.

## Open questions
1. What may stay at zero groups: the node's own key, its account's chain and D (home) are the node's identity, not a group's.
2. Kept copies and other user-chosen keeps: a group of their own (attributable, droppable), or an exception.
3. State attributable to a peer rather than a group (peer records, charges): attribute through the sync IDs shared with that peer, or a separate bounded budget the principle states.
4. Role-class history kept after unsyncing so a re-sync can verify: drop it too (fetched again on re-sync, Design principles: close leaks, don't shrink them) or keep.
