# Storage audit: every stored row has an owner
> Summary: Input to issues/reference-graph.md (Storage), which owns the design: an audit, written without Tess's review, of the row families on main that outlive what the node syncs, and how each would hang off an owner (a thing the node closure holds, a store entry of a synced sync ID, a peer record, or the node root). Used by the plan's closing count test; check each row before relying on it.
> Priority: normal
> Tags: sync, engine, retention

Tess's principle: every stored row is attributable to what the node holds, and releasing everything drops storage to the node root and the account's own things. Nothing may wait for a release's writes to be held elsewhere (issues/reference-graph.md, Principles): a statement here that implies it is wrong.

## Owners
Every durable row and blob has an owner; a row lives exactly while its owner does and goes in the transaction its last owner goes. Owners:
- **Whole things**: the node closure (issues/reference-graph.md: what the node root reaches by strongs). Such a thing keeps all it holds: content, role-class aspects, secrets, derived rows.
- **Store entries**: the entries of each sync ID in the sync set (or leaving it), which the required-set judgement (spec/sync-judgement.md §2) already limits to what S justifies: sync unit bodies, lasting headers, certificates of the chains S's things need, deposits. Engine data taken from an entry that is about no whole thing (another account's chain, a destroyed dependency's record and requests) is owned by the entries carrying it.
- **Peer records**: what a connection proved (a Prove's rotations, presence, charges, filters), owned by the record, and the record by its members (the sync IDs both share) or by being a node of this account.
- **The node root**: identity rows (`seed`, `hlc`, `account`, `u/`, `d/`) and the account root, held unconditionally.

The links between owners are counts over acyclic structure, so no walk beyond the closure is needed:
- entry → blob: `X/ b s` (the store keeps a blob while an entry names it);
- blob → commit: `bp/ c b`, `cb/ s b` (a commit is held while a part of it is on a whole thing, or a held blob of it was taken from an entry, or it is an own commit not yet held elsewhere);
- commit → thing: a thing is **known** while a held commit has a part on it or a held record blob names it;
- thing or commit → derived rows: keyed owner-first, dropped with it.

Cycles exist only in the closure (strongs), which the node closure's walk handles. Authority needs (record chains, holders' and authors' chains) need no walk of their own: what a held thing needs to verify travels as certificates in the required set of the sync IDs carrying it (spec/permissions.md §4), so it is owned by those entries and goes with the last.

## Exceptions on main and how each would be covered
Checked on main (2b5ac0318) unless marked "to confirm".
1. **Role-class state of unsynced things.** `retention::forget` with `Scope::Local` keeps `created.0`, `retention^.0`, `roles.0`, `keys.0`, `sync.0` and `secrets.0` (`forget::KEPT`, `Fate::Local`), so their role commits, headers, `node/metas`, `node/edges`, `node/keysets`, `node/epochs`, `node/walks`, thing lists (`tl/`, `tn/`, `tb/`), `g/`, `dw/` and secrets (`k/`) stay. Role commits are forgotten only by destruction (`retention/destroy.rs`) or as covered (`retention/mod.rs`). Covered: the thing is no longer whole; its role commits stay only where an entry still carries them (a certificate another synced S needs), else they go with the content.
2. **Other accounts' chains.** Rotations and keysets of an account taken from certificates or a Prove (`Engine::take_rotations`) are commits on that account's actor, which no forgetting names; `ra/` and `jc/` go only with things forgotten (`sync::held::forget_actor`). Covered: certificate-taken ones are owned by their entries, Prove-taken ones by the proving record; the account becomes unknown with its last held commit and its derived rows go.
3. **Blob rows after lost access.** `apply::unindex_unreceived` keeps a forgotten commit's `bp/` rows "with the blobs", and nothing drops them when the store drops the blob (`sync::bodies::unnote_blob` runs only on a marked forget or a bad reopen; `Forgotten::blobs` is filled only for unsyncing). Covered: the store's removal of a blob's last `X/` row writes a gone note in the same transaction; the engine drops `bp/ * b` and deletes the note (idempotent).
4. **Kept after a share ended** (`Core::stays_local`, `Status::kept`). `Node::unsync` forgets the content at once, but its `sh/` marks stay while the grant's commit is held, which is for good (a role commit), and exception 1 applies. Covered: a strong on the node root; releasing it removes the root, and `sh/` goes (the root's removal is the mark).
5. **Plain things leaving every closure** (to confirm by the test below). `forget_local` names only the things of stopped sync IDs and those under their secrets, so a thing without secrets of its own that leaves the closure while the sync ID that carried it stays (its sync unit no longer holding it) loses its entries there but keeps its engine state and commits. Its cleanup today is release by lifetimes, which the plan removes. Covered: it left the node closure, so it is released (issues/reference-graph.md, Holding and release).
6. **Destroyed for good** (`td/`, kept for good) and destroyed things' `kd/`, `kl/` (issues/destroyed-sync-id-never-left.md). Covered: owned by the destroying request's commit, which is held while the thing is whole or an entry carries the request (a dependent's sync ID: spec/commits.md §5 Destruction already keeps only what live things need). A node needing it no more stops emptying the sync IDs; other holders empty them. This settles destroyed-sync-id-never-left's question for a node not holding the thing.
7. **Dispute sides** (`sides`: one record, entries for good). Covered: one row per disputed actor, owned by it.
8. **Purge marks** on role-class aspects and `z/` rows of a fallen purge. Content-aspect marks (`p/`, `pn/`, `v/`, `w/`, `ro/`, `f/`) already go with the aspect (`destroy::forget_aspect_rows`). Covered by the thing's ownership; `z/` is found by its commit (key commit-first, as today).
9. **Peer records** (`core/store/src/record.rs`): bounded by `RECORD_BUDGET` (256 MiB) and least-recently-used, not by sync; presence rows outlive membership (issues/presence-outlives-membership.md); a joined link's kept peers (`I/p/`). Covered: a record goes with its last member sync ID unless the peer is a node of this account; presence follows that issue's P1 (a member leaving ends its rows); `I/p/` is owned by the link's target thing.
10. **Suspect repair rows** `I/s/ reporter thing ak` (osis-sync `inbox/suspect.rs`): each goes only when an entry shows it stale, so rows of a thing forgotten here, of a shredded S and of a reporter that never reports again stay for the node's life. Covered: keyed thing first, owned by the thing; a reporter's rows also go when its role on the thing ends.
11. **The account inbox's grant copies**: one per thing ever granted to the account, kept for good. They go with the plan: tickets replace them.
12. **Whole-table scans in forgetting** (issues/forget-whole-scans.md: pending rows, `x/` timers, `z/`, `fl/`). Covered by owner-first keys: timers found per commit part (key from the part's bounds, or a per-commit row), pending commits owned by the entries carrying them, `fl/` keyed thing first, `z/` by commit.
13. **Lifetime work rows** (`lw/`, `lh/`, `lp/`): go with the plan.

Already conforming: the sync store's per-sync-ID rows (`Store::shred`: entries, tombstones, path, usage, node log, `changed_at`, `N/`, `F/`, `R/`), `cp/` passes, content aspects and their rows, `hr/`/`hf/`, `fn/`, `cv/`, `ow/`, `ih/`, `T/`, `B/` (with its link), inbox fires (the inbox's history setting), `K/` (a kept-by-choice root).

## Purge tombstones
A lasting header is in the required set of each sync ID whose sync unit holds the purged thing (spec/commits.md §5), so it is kept and synced onward while any synced sync unit carries the thing, and goes with the last. Local purge marks are owned by the purged thing (whole) or the purge commit. A copy of the purged content arriving later through a peer that ignored the purge is accepted, as at a newcomer.

## Test
One count test: a node holding several things (shared with a peer, a purge, an admin dispute, certificates from other accounts, a retained copy, an ended share, an imported contact) releases everything; its store rows and bytes by family must equal those of a fresh node of the same account that synced nothing, and the work counted must be flat between n and 10n of what stays. Re-syncing must read as a node that never left.
