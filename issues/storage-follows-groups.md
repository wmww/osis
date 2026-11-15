# Storage follows synced groups
> Summary: Tess's principle: every stored row is attributable to what the node syncs, and unsyncing everything drops storage to a small floor (node identity and account root). Design: every row hangs off one owner (a thing the node closure holds whole, a store entry of a synced sync ID, a peer record, or the node root), through acyclic counted links (entry → blob → commit → thing → derived rows); the only reachability is the node closure (issues/refs-graph-lifetime.md). A row goes in the transaction its last owner goes. Lists every exception on main and how it is covered; four decisions for Tess.
> Priority: normal
> Tags: sync, engine, retention, tess-call

## For Tess
- **What users see.** A storage list: each synced group, and each thing kept by choice (a copy kept after a removal, a share that ended, an imported contact, a thing kept on this device only), with its size and what unsyncing it frees. Unsyncing everything leaves only the device's own identity and its account's records. Syncing a group again downloads and checks it in full, like a new device.
- **What it costs.** Re-syncing costs a full download, permission history included (already the rule for a new device). Forgetting costs what it forgets: no whole scans. A few row families get new keys or an index; two small "to do" rows make drops crash-safe.
- **Decisions.**
  1. **The floor.** What stays after unsyncing everything: the device's keys, clock and settings, and the account root (its keys and history, device list, synced-group list, sync record, profile, and its inbox, which holds one copy of each grant the account ever received, a few KB each). Options: (a) accept as is; (b) also let the grant copy of a role that ended leave after `ROLE_KEEP` (a device away longer then learns of its removal from the thing itself). Recommend (a), (b) as a low issue.
  2. **Kept-by-choice items** (retained copies, ended shares, imported contacts, device-only things) are entries in the storage list like groups, each unsyncable, and "unsync everything" includes them. Recommend yes.
  3. **Nothing of an unsynced group's past stays**: a later re-sync behaves as a new device. So a side chosen in an admin dispute is chosen again as a newcomer would; purged content a peer never purged can come back (you accepted this); a thing destroyed by purge can be re-minted here as at a newcomer (an existing limit). Recommend accept.
  4. **Requirements wording** (needs your sign-off), in Offline and network or Scale: "A node stores what it syncs, what it keeps by choice and its own and its account's identity: unsyncing everything returns it to that. Limit: data purged elsewhere can come back through a peer that kept it."

## Principle
Every durable row and blob has an owner; a row lives exactly while its owner does and goes in the transaction its last owner goes. Owners:
- **Whole things**: the node closure (issues/refs-graph-lifetime.md: what the node root reaches by strong references; on today's terms the synced group's closure, the things shared here, links being redeemed, and the kept-by-choice roots of decision 2). Such a thing keeps all it holds: content, role-class aspects, secrets, derived rows.
- **Store entries**: the entries of each sync ID in the sync set (or leaving it), which the required-set judgement (spec/sync-judgement.md §2) already limits to what S justifies: closure bodies, lasting headers, certificates of the chains S's things need, grant copies, inbox blobs. Engine data taken from an entry that is about no whole thing (another account's chain, a destroyed dependency's record and requests) is owned by the entries carrying it.
- **Peer records**: what a connection proved (a Prove's rotations, presence, charges, filters), owned by the record, and the record by its members (the sync IDs both share) or by being a node of this account.
- **The node root**: identity rows (`seed`, `hlc`, `account`, `u/`, `d/`) and the floor of decision 1 (D, held unconditionally).

The links between owners are counts over acyclic structure, so no walk beyond the closure is needed:
- entry → blob: `X/ b s` (the store keeps a blob while an entry names it);
- blob → commit: `bp/ c b`, `cb/ s b` (a commit is held while a part of it is on a whole thing, or a held blob of it was taken from an entry, or it is an own commit not yet held elsewhere);
- commit → thing: a thing is **known** while a held commit has a part on it or a held record blob names it;
- thing or commit → derived rows: keyed owner-first, dropped with it.

Cycles exist only in the closure (groups and references), which refs-graph-lifetime's reachability handles. Authority needs (record chains, holders' and authors' chains) need no walk of their own: what a held thing needs to verify travels as certificates in the required set of the sync IDs carrying it (spec/permissions.md §4), so it is owned by those entries and goes with the last.

## Exceptions on main and how each is covered
Checked on main (2b5ac0318) unless marked "to confirm".
1. **Role-class state of unsynced things.** `retention::forget` with `Scope::Local` keeps `created.0`, `retention^.0`, `roles.0`, `keys.0`, `sync.0` and `secrets.0` (`forget::KEPT`, `Fate::Local`), so their role commits, headers, `node/metas`, `node/edges`, `node/keysets`, `node/epochs`, `node/walks`, thing lists (`tl/`, `tn/`, `tb/`), `g/`, `dw/` and secrets (`k/`) stay. Role commits are forgotten only by destruction (`retention/destroy.rs`) or as covered (`retention/mod.rs`). Covered: the thing is no longer whole; its role commits stay only where an entry still carries them (a certificate another synced S needs, the account inbox's grant copy), else they go with the content.
2. **Other accounts' chains.** Rotations and keysets of an account taken from certificates or a Prove (`Engine::take_rotations`) are commits on that account's actor, which no forgetting names; `ra/` and `jc/` go only with things forgotten (`sync::held::forget_actor`). Covered: certificate-taken ones are owned by their entries, Prove-taken ones by the proving record; the account becomes unknown with its last held commit and its derived rows go.
3. **Blob rows after lost access.** `apply::unindex_unreceived` keeps a forgotten commit's `bp/` rows "with the blobs", and nothing drops them when the store drops the blob (`sync::bodies::unnote_blob` runs only on a marked forget or a bad reopen; `Forgotten::blobs` is filled only for unsyncing). Covered: the store's removal of a blob's last `X/` row writes a gone note in the same transaction; the engine drops `bp/ * b` and deletes the note (idempotent).
4. **Kept after a share ended** (`Core::stays_local`, `Status::kept`). `Node::unsync` forgets the content at once, but its `sh/` marks stay while the grant's commit is held, which is for good (a role commit), and exception 1 applies. Covered: a kept-by-choice root (decision 2); unsyncing removes the root, and `sh/` goes (the root's removal is the mark).
5. **Plain things leaving every closure** (to confirm by the test below). `forget_local` names only the things of stopped sync IDs and those under their secrets, so a thing without secrets of its own that leaves the closure while the sync ID that carried it stays (unlisted, its key home not in the closure) loses its entries there but keeps its engine state and commits. Its cleanup today is release by lifetimes, which refs-graph-lifetime removes. Covered: it is no longer whole, so it goes once its own writes are held elsewhere (below, Leaving).
6. **Destroyed for good** (`td/`, kept for good) and destroyed things' `kd/`, `kl/` (issues/destroyed-sync-id-never-left.md). Covered: owned by the destroying request's commit, which is held while the thing is whole or an entry carries the request (a dependent's sync ID: spec/commits.md §5 Destruction already keeps only what live things need). A node needing it no more stops emptying the sync IDs; other holders empty them. This settles destroyed-sync-id-never-left's question for a node not holding the thing.
7. **Dispute sides** (`sides`: one record, entries for good). Covered: one row per disputed actor, owned by it (decision 3).
8. **Purge marks** on role-class aspects and `z/` rows of a fallen purge. Content-aspect marks (`p/`, `pn/`, `v/`, `w/`, `ro/`, `f/`) already go with the aspect (`destroy::forget_aspect_rows`). Covered by the thing's ownership; `z/` is found by its commit (key commit-first, as today).
9. **Peer records** (`core/store/src/record.rs`): bounded by `RECORD_BUDGET` (256 MiB) and least-recently-used, not by sync; presence rows outlive membership (issues/presence-outlives-membership.md); a joined link's kept peers (`I/p/`). Covered: a record goes with its last member sync ID unless the peer is a node of this account; presence follows that issue's P1 (a member leaving ends its rows); `I/p/` is owned by the link's target thing.
10. **Suspect repair rows** `I/s/` (issues/suspect-rows-of-gone-things.md). Covered: keyed thing first, owned by the thing; a reporter's rows also go when its role on the thing ends.
11. **The account inbox's grant copies**: one per thing ever granted to the account, kept for good (spec/sync-inbox.md §5). Owned by the account root: the floor (decision 1).
12. **Whole-table scans in forgetting** (issues/forget-whole-scans.md: pending rows, `x/` timers, `z/`, `fl/`). Covered by owner-first keys: timers found per commit part (key from the part's bounds, or a per-commit row), pending commits owned by the entries carrying them, `fl/` keyed thing first, `z/` by commit.
13. **Lifetime work rows** (`lw/`, `lh/`, `lp/`): go with refs-graph-lifetime.

Already conforming: the sync store's per-sync-ID rows (`Store::shred`: entries, tombstones, path, usage, node log, `changed_at`, `N/`, `F/`, `R/`), `cp/` passes, content aspects and their rows, `hr/`/`hf/`, `fn/`, `cv/`, `ow/`, `ih/`, `T/`, `B/` (with its link), inbox blobs (`INBOX_LIFETIME`), `K/` (a kept-by-choice root).

## Leaving and crash safety
- A thing stops being whole in the transaction that changes the closure (refs-graph-lifetime). It goes once its own writes are held elsewhere, by the one wait rule (spec/sync-set.md §3), applied per own entry: for its own sync ID as today, and for a plain thing under the sync ID that carried it.
- Two outbox rows make the cross-store steps crash-safe without scans: a departure row per thing that left the closure while its drop waits (written in the closure change's transaction, removed by the forgetting transaction), and the store's blob-gone note (exception 3). A start resumes from them and from the store's sync IDs outside the sync set (`leave`, as today).
- Every other drop is in the transaction that removed the last owner.

## Purge tombstones
A lasting header is in the required set of each sync ID whose closure holds the purged thing (spec/commits.md §5), so it is kept and synced onward while any synced group carries the thing, and goes with the last. Local purge marks are owned by the purged thing (whole) or the purge commit. A copy of the purged content arriving later through a peer that ignored the purge is accepted (decision 3), as at a newcomer.

## Re-syncing
Syncing a thing again makes it whole; its sync IDs join the sync set with no rows, so their first pass is from the start and fetches the required set: content, permission history, certificates. Keys and sync IDs are found as a new device of the account finds them: the account inbox's grant copy (secrets, `sync.0`), the account's sync record (kept unread), the carrying group's sync ID (plain things). A thing read only through an actor the node no longer holds needs that actor synced first, as on a new device.

## Cost
- Steady state: no new per-write work; owner-first keys replace scan-keyed ones.
- Unsyncing: the closure change (refs-graph-lifetime's cost), then per leaving sync ID O(its entries), per blob gone O(its rows), per thing or commit gone O(its rows). What stays (shared with another group) costs O(1) per link checked.
- Storage list: one byte counter per owner, moved with each row write; a group's total and "frees if unsynced" computed on demand over its closure (user-triggered, rare: brute force).
- Re-sync: a new device's download (spec/requirements.md Scale).

## Test
One count test: a node syncing several groups (shared with a peer, a purge, an admin dispute, certificates from other accounts, a retained copy, an ended share, an imported contact) unsyncs everything; its store rows and bytes by family must equal those of a fresh node of the same account that synced nothing, and the work counted must be flat between n and 10n of what stays. Re-syncing must read as a node that never left.

## Plan
Model first (the closure part is refs-graph-lifetime's model). Then: the owner of each row family and its key; the outbox rows; the count test; the storage list API (notes/api-design.md).
