# Acting through holders without their content
> Summary: The decided direction (Tess, stage A2) for a role on C through holders A and B used without downloading A and B: roles never feed what syncs; a node syncing C holds for keys (roster, role commits, own key boxes; no content) every holder on every path giving its account a role on C; no taking of grants; the availability gap accepted. With the measured baseline, the candidates costed on the same scenarios and why (b) was chosen, the weak spots, what goes at A2, and the model (held-model `closure::keys`: properties i to v, controls, counts, hand worlds) with its finding: the lean for finding the paths, the reference naming its holders then C's roster, misses honest paths and makes a role depend on when a node synced; the two complete searches each cost something the direction refused. Nothing here is built or in spec.

**Principle: roles never feed what syncs.** What a node syncs comes from its strongs alone. A role decides only what the node may do with what it syncs, and which holders' key parts it fetches to do it. Choosing to sync C is the consent: a stranger's grant matters only where the stranger's thing is on a path to something the node syncs, and C's admins (or a chain's) arranged that path.

## The direction
1. **No taking.** A grant gives its holder a role; nothing takes it up. A node's role on a thing it syncs is its account's effective role over that thing's real holder chains (spec/permissions.md §1): a function of what it chose to sync and the world, never of what happens to be held, so the convergence class of roles counted over held role commits (Convergence below) cannot arise.
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
The convergence class (issues/roles-apart-from-syncing.md, Why roles counting over every held role commit fails) came from an edge counting because its role commit happened to be held. Under the direction the role is defined without reference to holdings: the node's role on a thing it syncs is the account's effective role over that thing's edges in the world. A node computes it from the key parts of the holders on its paths, which it fetches for exactly that reason; an edge in a certificate that arrived for another reason either is on such a path (and counts anyway) or is not (and gives no role, since no path from an own actor runs through it). What is synced is the least fixpoint of: the node root; the targets of strongs of things the node reads; read-ness by that role. The held-for-keys set is the holders on every path from an own actor to a thing in it. Dropping the last strong below a holder shrinks both: the holder is no longer held for keys, its secrets go, and the role goes by the one lost-access rule. spec/requirements.md "Referencing a thing grants no rights, and removing a reference revokes none" holds as written: the reference chooses what is held, the grant gives the role.

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
4. **A new way to hold a thing** in the closure walk (beside read, kept unread and on a ticket's word), in the least settled code: lost access, release, what a held thing needs, sync status per class (a node holding H for keys is no source of H's content and its complete pass is of role entries). Modelled (The model).
5. **Role entries are wider than keys**: the class also holds commits carrying purge requests and blobs they link (spec/sync-ids.md §6). Either the filter takes them (small) or the class is narrowed.

## Open: finding the paths
The fetch set is defined (every holder on every path from an own actor to a synced thing); how a node finds it is open, and the model (The model, below) shows the coordinator's lean, (p3) then (p2), does not find it. C is opaque until its first box arrives, and an edge "B holds a role on C" travels under B's sync ID, so a search runs from the node's own actors down or from C's roster up.

Searches modelled (held-model `Search`), by what each reads:
- **(p1) by lists** (`Lists`): the edge list (target and role per grant, tens of bytes each) of every holder an own actor reaches by grants; key parts only for holders on a path.
- **(p3) the reference names its holders** (`Hint`): whoever makes the strong states the holders it found C through, as a write states its path (A1). The node makes keyed lookups ("does h hold a role on x") among its own actors, the holders named and the target. A hint chooses only where to look; the role comes from the real chain.
- **(p2) bounded by C** (`Roster`): keyed lookups from what the node has opened to the holders named by the rosters of the things it reads.
- **The lean, (p3) then (p2)** (`HintRoster`), and the lean reading also the roster of every holder on a path found (`HintRosterDeep`).
- **Backward by rosters** (`Back`): the roster of every thing on a chain of grants ending at a thing the strongs reach; key parts only for holders on a path. Not buildable as the direction stands: a roster is sealed under its thing's secrets, so it needs a holder's roster readable by the readers of what the holder has a role on.

**Finding: (p3) and (p2) miss honest paths, alone and together.** A keyed lookup needs both ends named, and the middle of a path is named nowhere the node can read: not by a strong made before the path existed or by someone who found C another way, and not by C's roster, which names the last holder only. The smallest worlds, each a default test (`finding_*`):
1. **A better path above a named holder.** The account read on H and admin on G, G admin on H, H admin on C; the strong names H. The world gives admin on C, the lean shows read: G is in no roster the node reads. Three things, four grants. (Deep finds G in H's roster.)
2. **Two hops from what it reads.** The account read on C directly, and read on X, X on Y, Y on Z, Z on C. C's roster names Z; the account holds no grant on Z and Z's roster is closed to it. Lean and deep never hold X, Y and Z for keys, and with the direct grant revoked both lose C while the world gives read. The role form at three things and four grants: the account read on C and admin on X, X admin on Y, Y admin on C; the world gives admin, lean and deep show read.
3. **A node arriving later shows less.** Hand world 2 (A to C and D to C, the strong naming A) with A revoked on C: the node that was there holds D, which C's roster named while it could read C, and writes C; a node arriving afterwards with the same strong looks up A and C, finds no path, and cannot read C to learn of D. Under the lean a role is no function of strongs and chains (property (i)); the same holds for (p3) alone, where a holder reached through a strong inside a thing stays known after the path to that thing goes.

What the two complete searches cost:
- **(p1)** finds every path and fetches no key part and gives no role at a stranger's say, but reads lists at it: one entry per grant of every holder the account reaches by grants. A stranger's X, granted to the account and holding roles on n things: n + 1 entries (hand world 3: 6 and 51 at n = 5 and 50); A holding roles on k things: k entries at first sync (hand world 6). No bound in what strangers build.
- **Backward by rosters** finds every path and reads nothing at a stranger's say: a thing joins the chains above C only by an admin of C or of a holder above it. It reads the roster of every holder above C, on a path of the account or not: m entries for a holder of m members at first sync (hand world 6: 12 and 102 at m = 10 and 100) and an entry per member granted after, against "a grant added costs nothing below H" (Baseline). Every reader of C then learns who holds every thing above C: within spec/requirements.md (readers may learn who holds roles on it, directly or through other things), more than Privacy (b) says. And the roster must be made readable down the edge (a roster secret boxed with the edge piece, say), which is new design.

Choices, none taken (the coordinator's, and Tess's where a requirement moves):
- **(p1) with a bound on list reads.** The bound is a picked number over what strangers build (notes/arbitrary-values.md), and past it a real path is missed, so (i) fails again at the bound.
- **Backward by rosters**: design the roster's readability down an edge, accept roster-sized reads and the wider privacy line.
- **A role only through holders somebody named**: make what a reference names part of the definition. It gives up "a role counts wherever its grants are held" for paths nobody named (worlds 1 and 2), and needs a rule that makes it a function of the strongs and chains, which (p3) as modelled is not (world 3): a requirements question.
- **Who may grant to a thing** (A5): if a thing's admins gate the grants naming it, (p1)'s lists are bounded by that consent. Unless A5 wants the gate for its own reasons this is taking under another name.

## What goes at A2
notes/node-closure.md clauses 3 and 7 (Roles taken up) and "taking" throughout: spec/sync-set.md §2 Taken up, spec/sync-inbox.md §5 "Nothing before the strong" and "only accepting takes a grant up", spec/permissions.md §3's "a grant no longer taken up" and the account's own grant counting only while taken up, notes/write-path-design.md §4 "What A takes" as a condition of a role (whether A5 keeps a gate on what a thing's unit stores is A5's to state), A2's taken-grants brief; the account root counting for keys-open travel only on things it reaches (spec/sync-judgement.md §2); the ticket-word rules standing in for role commits a node cannot yet read (spec/sync-set.md §2 What a held ticket does, clause 8) to be re-read against it; the holder piece as a copy of X's whole `secrets.0` part (direction 3). It closes gap 2 of issues/roles-apart-from-syncing.md. A4's "members enter what A holds roles on by its boxes under A's sync ID" is this rule at the node's first hop: a node may hold its account for keys only, so pairing no longer means syncing the account's whole unit.

## With A2
One design, two halves, one blob format (the copy per (commit, thing)):
- what a reader needs to **judge** a held write rides down in the unit that holds the write (A2 evidence, a function of holdings);
- what a node needs to **act** through a holder is pulled from the holder (its key part, own boxes), a function of strongs and the holders' real chains.
The edge piece is A2's "a holder's grants under the holder's sync ID" (every grant naming it; notes/a2-spec/README.md Open 1), cut to the boxes to that holder.

## The model
held-model `closure::keys` (core/test/held-model/src/closure/keys.rs, tests/it/spec_holders.rs; core/test/held-model/README.md, Holder access). It precedes any spec or code of this half of A2.

**What it holds.**
- `oracle`: the direction's definition as a function of the world: roles as the own actors' effective roles over the world's grants; what is synced as the walk from the root strongs reading by those roles; `Closure::for_keys`, the holders on every path of grants to a synced thing less what is held whole.
- `Keys`: per thing its edges, a keyset per epoch and a box per holder per epoch. A revocation rotates the target at once, boxed to the holders left at their current epochs, and leaves everything below it stale until next written.
- `Node`: a search (above), a source (the sync IDs and key parts it can reach in one sync) and a ledger counting once each edge write, keyset, box, list entry, keyed lookup and content version it fetches.
- Abstracted: every thing independent; holding an epoch gives the earlier ones; a rotation is readable under the epoch before, so a thing's own sync ID gives every box but the first; a holder's part is readable with the holder's current epoch; a keyless grant is on no path. Validity and which path a write states are roles-model `paths`.

**Properties** (`check`: per world and rule, by name), over the small family and random histories:
- (i) Roles, and what is read and held, are the oracle's; the same with a certificate of every grant not standing held too; under relabelling; and a node that was there through a revocation shows what one arriving after it shows.
- (ii) A grant naming the account or a holder, on a thing on no path to a synced thing, changes no role and no fetch (key parts and lists counted apart).
- (iii) No content of a thing not synced is fetched.
- (iv) After a revocation, heard from the synced things and the key parts already held: what the world leaves writable is writable, no holder is newly opened, and a thing with no path left loses its secrets. Then, synced with everything, the node shows the oracle's.
- (v) A content change of a thing not synced fetches nothing; the counts of hand world 6.
- The fixpoint's own: a sync settles and a second fetches nothing; with every strong dropped nothing is held for keys.

**The small family**: 1,166,345 worlds. Three things with every grant among them and the account absent, read or admin, and with up to four grants one of them write; four things with up to six admin grants, and with up to three one of them read; root strongs to one or two things; no strong inside a thing or one; each strong naming the holders of one of the account's paths to its target. Worlds failing, of all (`explore`, `OSIS_HOLDERS_STRIDE=1`):

| property | (p1) lists | (p3) hint | (p2) roster | lean | deep | backward |
|---|---|---|---|---|---|---|
| (i) roles the oracle's | 0 | 7,290 | 146,330 | 220 | 100 | 0 |
| (i) holders the oracle's, roles equal | 0 | 113,925 | 12,424 | 14,421 | 5,228 | 0 |
| (i) a late node alike | 0 | 16,534 | 161,742 | 93,548 | 99,694 | 0 |
| (i) certificates, relabelling | 0 | 0 | 0 | 0 | 0 | 0 |
| (ii) roles, key parts | 0 | 0 | 0 | 0 | 0 | 0 |
| (ii) lists | 418,604 | 0 | 0 | 0 | 0 | 0 |
| (iii), (v) content | 0 | 0 | 0 | 0 | 0 | 0 |
| (iv) writable on hearing it | 0 | 62,563 | 121,264 | 8,343 | 4,038 | 0 |
| (iv) no holder newly opened, lost access | 0 | 0 | 0 | 0 | 0 | 0 |
| (iv) then the oracle's | 0 | 121,215 | 155,586 | 14,641 | 5,328 | 0 |
| settles, fixpoint | 0 | 0 | 0 | 0 | 0 | 0 |

**Controls**, each on (p1), over every fourth world; each fails its property: roles from every held edge, (i) certificates (63,528 worlds; hand world 10); roles from reached, the rule before (`World::roles_from_reached`), (i) roles (40,476; hand world 1, where C alone gives no role); following every grant naming the account, (ii) key parts (117,579; hand world 3); key parts of the chosen write path only, (iv) a holder newly opened (44,473; hand world 2); whole box sets, (v) in hand world 6 (boxes fetched at a member's removal 10 and 100 by m, at the rotations below 1 and 10 by k).

**(v) counts** (hand world 6: A with m members holding admin on k things, the node syncing one through A; (m, k) = (10, 1), (100, 1), (10, 10), (100, 10)). At every size and under every search: first sync 2 keysets and 2 boxes; A's content changing, nothing; a member removed, A's keyset and the node's own box; C's rotation, its keyset and the node's own box. What the search reads at first beyond the path's two edge pieces: (p1) 2, 2, 11, 11; lean 4, 4, 4, 4; deep 44, 404, 44, 404; backward 12, 102, 12, 102.

**Random histories** (grants, revocations, rotations owed, content changes, strongs added and dropped with their hints, a stranger's thing granted to the account or a holder; three nodes with the same strongs syncing at random moments from random sources; two more that after half the steps reach only a store keeping what they sync unread, with every key part there or none), 600 histories of 40 steps (`holder_access_histories_plain`). Under (p1) and backward every node ends as the oracle and alike whatever the order, the node behind the store with key parts included; behind the store without them the node is left behind in 337 (the availability gap, direction 4). Under the lean the nodes end unlike the oracle in 99 histories and unlike each other in 12; deep 95 and 13; (p3) 129 and 12; (p2) 130 and 12.

**Hand worlds**, each a default test (`hw1` to `hw11`): 1 A to B to C, C alone synced (iii, v, and the rule before giving nothing); 2 two paths, one revoked, then the other (iv); 3 a stranger's X holding n things (ii, list reads per search); 4 X put on a path by C's admin and taken off; 5 the strong dropped; 6 churn at m and k (v); 7 a read hop gives read; 8 a cycle of holders, with and without the keyless rule; 9 A also synced whole; 10 the old class (a certificate off every path; a revoked grant's certificate); 11 the availability gap, without and with A's key part at the store.

**Not modelled**:
- The joint property with held-model `evidence` (a node holding one sync ID plus the key parts its paths name judges and acts as one holding everything): it waits on the search, since "the key parts its paths name" is what is open.
- Own boxes against "a commit applies with all its pages" (weak spot 1) and role entries carrying purge requests (weak spot 5): the ledger counts boxes and entries, not pages.
- The sync differential's `Model::closure` (core/sync/tests/it/harness/history.rs) takes `keys::oracle` at the build brief; `closure_reaching` and `World::roles_from_reached` go then.
