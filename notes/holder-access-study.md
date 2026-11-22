# Acting through holders without their content
> Summary: The decided direction (Tess, stage A2) for a role on C through holders A and B used without downloading A and B: roles never feed what syncs; a node syncing C holds for keys (roster, role commits, own key boxes; no content) every holder on every path giving its account a role on C; no taking of grants; the availability gap accepted. With the measured baseline, the candidates costed on the same scenarios and why (b) was chosen, the weak spots, what goes at A2, and the modelling plan (where, properties i to v, generators, hand worlds) that comes before any build. Nothing here is built or in spec.

**Principle: roles never feed what syncs.** What a node syncs comes from its strongs alone. A role decides only what the node may do with what it syncs, and which holders' key parts it fetches to do it. Choosing to sync C is the consent: a stranger's grant matters only where the stranger's thing is on a path to something the node syncs, and C's admins (or a chain's) arranged that path.

## The direction
1. **No taking.** A grant gives its holder a role; nothing takes it up. A node's role on a thing it syncs is its account's effective role over that thing's real holder chains (spec/permissions.md §1): a function of what it chose to sync and the world, never of what happens to be held, so the old convergence class (Convergence below) cannot return.
2. **Held for keys.** Syncing C pulls the **key part** of every holder on **every** path from an own actor to C that gives a role (roster, role commits and certificates, the key boxes the node opens; no content, no blobs), from each holder's own sync ID, by role entries alone (spec/sync-ids.md §6). Every path, not only the one a write picks (core picks per write: the shortest path giving the needed role, `engine/write.rs` `role_path`/`path_with`), so a revoked path never leaves C unwritable while another is fetched.
3. **Own boxes only.** A node fetches only the boxes it opens, never a holder's whole box set (issues/holder-key-churn.md). Any node holding a holder's key part can serve it.
4. **Availability gap accepted.** A node whose only reachable sources keep C unread and hold no key part of A or B gets no key change of A there. A store meant to serve C to people acting through A keeps A's and B's key parts too: the user's or app's configuration (a store keeping C unread cannot read C's roster, so it is told), no new mechanism. Revisit if the gap bites.
5. **Lands with A2** (evidence per sync unit) as one design, before A4.

## What a path needs
For each edge "H holds a role on X" there is one **edge piece**: the edge write (`roles.0` on X), X's boxes to H, X's sync ID. To act on X through own actor n and holders H1..Hd a node needs the d+1 edge pieces of its path, each holder's current keyset commit, and nothing else of any holder. That is about 11 KB per holder (computed: `keys.0` 6.3 KB, the node's own boxes 2.4 to 4.3 KB, an edge piece 2.1 KB), whatever the holders' sizes and rosters. Every path held, not one: the union of the holders on them, 11 KB each.

Where edge pieces travel today: only under the holder's own sync ID, with the holder's whole sync unit (spec/sync-judgement.md §2, a grant naming a holder travels under the holder's sync ID), so a path through a 30 GB A costs 30 GB. X's own sync ID cannot give a first box: its role commits are wrapped under X's secrets.

## Baseline: what already churns
Measured in the engine (the commits of `grant`, `demote` and `ensure_rotated` packaged as `thing_cost::what_a_reader_costs` packages its grant: holder H with m writer members, H write on X, X's roster its admin and H; sync entries and stamps not counted), with notes/thing-cost.md and notes/a2-spec/README.md For Tess 6:

| event | bytes | who downloads it |
|---|---|---|
| a member granted on H (read) | one commit, 4.0 KB | every reader of H; nothing below H |
| H granted write on X (granter holds H's secret: symmetric boxes) | one commit, 2.1 KB (`secrets.0` 1.15 KB) | X's syncers; copied under H's sync ID for every reader of H |
| a member removed from H | H's rotation: 2.7 KB + 4.9 KB per remaining writer (12.5 KB at 2 holders, 32.2 KB at 6; a reader's boxes are 2.7 KB) | every reader of H, every box of it (a commit applies only with all its pages, spec/crdt.md §8) |
| then each independent X that H holds a role on | X's rotation when next written, 11.7 KB + boxes of X's other holders (about 21 KB seen by a document's reader, notes/a2-spec) | X's syncers; and its whole `secrets.0` part (5.0 KB here, every box of X) plus `sync.0` is copied under H's sync ID for every reader of H (engine `holder_piece`) |
| H's content changes | the change | every syncer of H's sync ID, path users included |

So with m members and k independent things below H, one removal costs, by design and before any change here:
- **H's rotation, in m**: 52 KB at 10 members, 4.9 MB at 1,000 (2.7 MB if they only read), downloaded by each member: m times that across the network. 100,000 direct members cannot exist (`MAX_CLAIMS` 65,536); nested three deep at fan-out 47 a removal costs every member the top rotation (about 230 KB), and the members of the two groups below it theirs.
- **A rotation of every thing below H, in k**: lazy (stale boxes, spec/crypto.md §4), 11.7 KB or more each, required for confidentiality (spec/requirements.md Cost: "in proportion to the rosters of what it could read"). Fundamental; candidates are judged against it.
- **A copy of each of those rotations' boxes to every reader of H, in k times m**: about 5.5 KB per thing below, to every member, whether or not it syncs the thing. Not fundamental: a reader of X needs its box to H from X's own rotation commit, which it opens under the epoch before; only a node entering X for the first time needs the copy, and only the boxes to H (direction 3).

A grant added costs nothing below H, and that must stay (notes/write-path-design.md §2, Not every actor that could write).

## Candidates
**(a) Key parts carried down.** Each unit carries, beside its bodies, the key part of every holder above it, as shared blobs listed under the unit's sync ID and stored once per node. A node syncing X opens only X's sync ID.

**(b) Key parts pulled** (chosen). Nothing more is listed under X. A node syncing X also syncs, for each holder on its paths, that holder's sync ID restricted to role entries: the holder is **held for keys**.

**(c) A key unit per thing.** Every independent thing has two sync IDs, one for its key part and one for its sync unit; paths pull the first.

(a) and (b) are one mechanism with two placements: the same blobs (A2's copy per (commit, thing), one blob wrapped under each sync ID that needs it, notes/write-path-design.md §2 E3), stored once per node either way. They differ only in **which sync ID's log lists the blob**: that decides who writes an entry when a holder changes (a: a writer of every unit below, k entries per change; b: nobody, the holder's own log has it) and who can serve it (a: whoever serves X; b: whoever holds H's key part). (c) is (b) with a second sync ID per thing: stores already tell role entries apart by stamp domain, so the split hides nothing more and doubles the cost per sync ID that stage S1 cuts (issues/many-sync-ids-cost.md).

The half of (a) that judging needs is built or planned and stays: X's sync ID carries the edge writes its held commits' paths use (A2 evidence) and the keyset commits its boxes name (spec/crypto.md §4 Carried), both functions of what X holds. What (a) would add is the boxes.

### Costs
H with m members; k independent things below it; d holders on the path; "whole" is role commits fetched as they are today, "own boxes" with direction 3 (a node fetches the boxes it opens and the edge pieces of its paths).

| scenario | today | (a) carried down | (b) pulled, whole | (b) pulled, own boxes (decided) |
|---|---|---|---|---|
| first sync of a 1 MB C through A (30 GB) and B, 10 members each, each holding 100 things | 30 GB + B + 1 MB | 1 MB + about 105 KB, but no first box (below) | 1 MB + about 100 KB of rosters and boxes + 1.1 MB of A's and B's edge pieces | 1 MB + about 25 KB |
| key part held per holder, m = 10 / 1,000 | whole unit | 50 KB / 4.4 MB, stored also by every store of every unit below | 50 KB / 4.4 MB at path users only | 11 KB / 11 KB |
| 100,000 members | nested only | nested only; every level's part under every unit below | nested only | 11 KB per level |
| depth d | d whole units | d key parts under each unit | d key parts | d × 11 KB |
| a node holding n units under one holder | the holder's unit once | the key part once + n entries per change of it | the key part once | the same |
| a member removed from H | baseline | baseline + one entry (153 B bare, about 1.2 KB measured for an enclosing unit's, issues/enclosing-unit-commit-cost.md) under each of the k units, written by a writer of that unit holding H's rotation; the rotation's bytes (4.9 MB at 1,000) at each unit's stores | baseline, nothing added | own box of H's rotation, and X's rotation for each X the node syncs |
| a member granted on H | 4.0 KB under H | + k entries if rosters ride down; nothing if only edges between holders do | nothing added | nothing added |
| H granted a role on a new X | 2.1 KB under X, a copy under H | + its piece under every unit below X | nothing added | nothing added |
| H's content changes | every path user downloads it | nothing | nothing | nothing |

### Privacy
- (a): every reader of X receives the rosters and box lists of every holder above X. Within spec/requirements.md (readers may learn who holds roles on it, directly or through other things), but far more than a judgement needs. A node keeping X unread sees one shared blob listed under every unit below a holder when that holder's roster changes, and its size: which of its units share a holder, when it changes and how big it is.
- (b): a node holding H for keys learns what a reader of H learns today less its content (H's roster, which members see anyway; the things H holds roles on). A node keeping X unread learns nothing of H. A store of H sees which peers pull role entries only (network metadata). With own boxes, a member no longer receives the box list of every thing H holds.

### Hostile input
- A stranger's grant naming the account, or naming a holder the account acts through, changes no fetch and no role unless its target is on a path to something the node syncs; there it is a grant like any other, on a thing whose admins put it on that path. The grant itself sits under the named holder's sync ID as today (bounded by who may grant to a thing, A5).
- (a): the node opens only sync IDs its strongs chose. A writer of X can list junk as ancestors' parts, bounded as any writer.
- (b): the node also opens the sync IDs of holders it did not name one by one. Each is on a chain of edges from an own actor to a thing the node syncs, so each was put there by the admins of the next thing down. A writer of H attaching things costs a path user nothing unless a strong reaches the thing (own boxes; but see Open, path search).

### Convergence
The old class (issues/roles-apart-from-syncing.md, Why roles counting over every held role commit fails) came from an edge counting because its role commit happened to be held. Under the direction the role is defined without reference to holdings: the node's role on a thing it syncs is the account's effective role over that thing's edges in the world. A node computes it from the key parts of the holders on its paths, which it fetches for exactly that reason; an edge in a certificate that arrived for another reason either is on such a path (and counts anyway) or is not (and gives no role, since no path from an own actor runs through it). What is synced is the least fixpoint of: the node root; the targets of strongs of things the node reads; read-ness by that role. The held-for-keys set is the holders on every path from an own actor to a thing in it. Dropping the last strong below a holder shrinks both: the holder is no longer held for keys, its secrets go, and the role goes by the one lost-access rule. spec/requirements.md "Referencing a thing grants no rights, and removing a reference revokes none" holds as written: the reference chooses what is held, the grant gives the role.

### The first box
(a) fails here alone: a node that never held X cannot open X's sync ID at a store (no credential) nor the copies wrapped under it. Tagging entries so that a holder's key opens them, or listing every holder thing in X's claim set with an entry box (spec/sync-ids.md §3), makes X's stores serve key material by holder, and only an admin issues steps while any writer rotates. (b) has no such gap: the node reads H by H's own box to it, and H's key part holds X's boxes to H.

### Rejected
- (a) carried down: an entry under every unit below a holder per change of the holder (the cost notes/write-path-design.md §2 refused for rosters), roster-sized rotations at every store of every small thing below, no first box. Its availability advantage is direction 4's gap.
- (c) a key unit per thing: a second sync ID per thing for a split stores already make by stamp domain.
- A pointer to each holder's key part in every unit below (to close the gap): one entry per unit per holder change, and stores learn which units share a holder.
- The strong stays the choice, with boxes carried down the keys-open chain (the issue's option 1): a path still costs A's 30 GB.
- Roles decide what is fetched from every grant naming the account (option 3): a stranger's grant makes the node fetch.
- Taking (by the account at a strong, or by a holder's writers): a second consent beside choosing to sync, and the source of rules that shift a role by what is reached (clauses 3 and 7 below); unneeded once a stranger's grant off every path changes nothing.
- Key parts of the path a write would pick only: a revoked path leaves C unwritable until another path's key parts arrive.

## Weak spots
1. **Own boxes touch "a commit applies with all its pages"** for role parts: fetching only the pages a node opens makes unfetched pages a may-hold state (already one, spec/sync-judgement.md §2); a node that may rotate H still needs them all, and what a re-sealer and the stale-box rules read of the other boxes decides how far it goes (issues/holder-key-churn.md).
2. **Finding the paths** (Open below).
3. **Availability** (direction 4): a member through H served only by a node keeping X unread gets X's rotations there but not H's. X already carries H's keyset commits (Carried); carrying H's boxes too is (a)'s cost again.
4. **A new way to hold a thing** in the closure walk (beside read, kept unread and on a ticket's word), in the least settled code: lost access, release, what a held thing needs, sync status per class (a node holding H for keys is no source of H's content and its complete pass is of role entries). Modelled first (below).
5. **Role entries are wider than keys**: the class also holds commits carrying purge requests and blobs they link (spec/sync-ids.md §6). Either the filter takes them (small) or the class is narrowed.

## Open: finding the paths
The fetch set is defined (every holder on every path from an own actor to a synced thing); how a node finds it is not. C is opaque until its first box arrives, and an edge "B holds a role on C" travels under B's sync ID, so the search runs from the node's own actors down. Read naively it opens the edge list (target and role per grant, tens of bytes each) of every holder an own actor reaches by grants, a stranger's thing and whatever it holds roles on included: list reads at a stranger's say, without bound, against property (ii). Candidates, to be settled in the model before build:
- **(p1) Search by lists, fetch by path**: read the edge lists of reachable holders, fetch key parts only for holders on a path. (ii) holds for key parts and roles, not for list reads; needs a bound or a stated cost.
- **(p2) Search bounded by C**: once C is readable by any path, C's roster names its holders; the search reads lists only of holders on chains ending at those. Gives (iv) by matching C's roster on each rotation; the first path still needs (p1) or (p3).
- **(p3) The reference names its holders**: whoever makes the strong (or the listing it was picked from, notes/realms.md Seeing the contents) states the holders it found C through, as a write states its path (A1). A hint chooses only where to look; the role still comes from the real chain. Cost in the path; a hint gone stale falls back to (p2).

## What goes at A2
notes/node-closure.md clauses 3 and 7 (Roles taken up) and "taking" throughout: spec/sync-set.md §2 Taken up, spec/sync-inbox.md §5 "Nothing before the strong" and "only accepting takes a grant up", spec/permissions.md §3's "a grant no longer taken up" and the account's own grant counting only while taken up, notes/write-path-design.md §4 "What A takes" as a condition of a role (whether A5 keeps a gate on what a thing's unit stores is A5's to state), A2's taken-grants brief; the account root counting for keys-open travel only on things it reaches (spec/sync-judgement.md §2); the ticket-word rules standing in for role commits a node cannot yet read (spec/sync-set.md §2 What a held ticket does, clause 8) to be re-read against it; the holder piece as a copy of X's whole `secrets.0` part (direction 3). It closes gap 2 of issues/roles-apart-from-syncing.md. A4's "members enter what A holds roles on by its boxes under A's sync ID" is this rule at the node's first hop: a node may hold its account for keys only, so pairing no longer means syncing the account's whole unit.

## With A2
One design, two halves, one blob format (the copy per (commit, thing)):
- what a reader needs to **judge** a held write rides down in the unit that holds the write (A2 evidence, a function of holdings);
- what a node needs to **act** through a holder is pulled from the holder (its key part, own boxes), a function of strongs and the holders' real chains.
The edge piece is A2's "a holder's grants under the holder's sync ID" (every grant naming it; notes/a2-spec/README.md Open 1), cut to the boxes to that holder.

## Modelling plan
Before any spec or code brief of this half of A2.

**Where.**
- **held-model `closure`** (core/test/held-model/src/closure.rs, tests/it/spec_closure.rs; notes/closure-model.md) is the home: it already has the reference graph, sync units, the node closure as a least fixpoint over keys and sync secrets, and `roles_from_reached` (the clause-3 oracle that goes). Added: a key part per independent thing (its edges and a box per holder per epoch), a revocation or member removal bumping the target's epoch with boxes to its current holders, a `for_keys` set in `Closure` beside `read`, `stored` and `held`, roles as the effective role over the world's edges for each synced thing, and a fetch ledger (role entries and boxes fetched per node per event, content bytes kept apart) for property (v). Each path-search candidate (p1 to p3) as a `Search` variant.
- **held-model `evidence`**: the joint property, a node holding one sync ID plus the key parts its paths name judges and acts as one holding everything, once `closure`'s properties hold (A2's two halves checked together).
- **The sync differential's `Model::closure`** (core/sync/tests/it/harness/history.rs) takes the new oracle at the build brief; `closure_reaching` and its reached loop go. Not a modelling step.
- **roles-model `paths`**: unchanged. Validity of each edge is its job; here edges are taken as valid and roles are widest paths, so the two compose. (iv) involves the write path's choice only through "some held path gives write".

**Properties.**
- (i) **Roles are a function of strongs and holder chains**: equal at every node with the same strongs whatever else it holds (extra certificates, evidence copies, records), under relabelling of things and every delivery order (`gen` shuffle).
- (ii) **A stranger's grant changes no fetch**: adding a grant on a thing on no path to a synced thing leaves the fetch ledger and every role unchanged (lists included, or stated per the chosen search).
- (iii) **A to B to C**: syncing C alone reads and writes C, fetching A's and B's key parts and nothing of their content.
- (iv) **A path revoked**: with two paths to C, revoking one leaves C writable at once, with no fetch outstanding (the other path's key part already held); revoking the last drops C's secrets by lost access.
- (v) **Cost**: a holder's content change downloads nothing at a node syncing only C below it; a member removed from a holder costs a path user its own box of the rotation (and its own box of each synced thing's rotation), constant in m and k, counted at n and 10n.
- Plus the fixpoint's own: dropping the last strong below a holder removes it from `for_keys`; cycles among holders terminate; held for keys and held whole at once is held whole.

**Negative controls** (each must fail its property): roles from every held edge (i); following every grant naming the account (ii); key parts of the chosen write path only (iv); fetching a holder's whole box set (v).

**Generators.**
- An exhaustive small family: one account with one node, up to four independent things, each edge among {account, things} absent or read, write, admin, the node root's strongs to one or two things, strongs inside things (so read-ness feeds the walk); with each world's relabellings.
- A random history generator over that world: grants, revocations, member removals, content changes, strongs added and dropped, a stranger granting the account or a holder, delivered in random orders to two or three nodes and a store keeping C unread with or without configured key parts.

**Hand worlds.**
1. A to B to C, node syncs C alone (iii, v).
2. A to C and D to C; A revoked on C (iv); then D revoked (lost access).
3. A stranger grants the account write on X, X holding roles on things the stranger builds without bound; X on no path (ii, and each search's list reads).
4. The same X put on a path by C's admin granting X a role on C, then removed (held for keys and back).
5. The strong to C dropped: A and B leave `for_keys`, C's secrets go.
6. A's content changes and a member of A is removed, m = 10 and 100, k = 1 and 10 (v).
7. A read hop: A read on B, B admin on C: role on C is read.
8. A cycle: A holds a role on B and B on A, both above C.
9. The node also syncs A whole: held whole, not twice.
10. The old class: a certificate naming G on H arriving with another write, G on no path from an own actor (no role); a grant on T1 seen only through T2's certificates (counts iff a real path exists, whichever certificates arrived).
11. The availability gap: a store keeping C unread serves a node acting through A, without and with A's key part configured there.
