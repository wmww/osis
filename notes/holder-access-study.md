# Acting through holders without their content (study)
> Summary: Design study for Tess's call in issues/roles-apart-from-syncing.md (a role on C through A and B must be usable without downloading A and B): what a role or key change costs today (measured), the three candidates costed on the same scenarios (key parts carried down under each unit; holders' key parts pulled; a separate key unit), why the first two are one mechanism with two placements, the recommendation (a thing is held for keys: only the role entries of its sync ID, for each holder on a taken path to something the node's strongs reach), its weak spots, what it replaces, where it lands, and the questions left for Tess. Nothing here is built or in spec.

**Principle proposed: acting through a thing needs its keys, never its content.** A sync ID has two classes of entry, which stores already tell apart (spec/sync-ids.md §6 Role entries): the thing's **key part** (its role commits: roster, keysets, boxes, `sync.0`; and its taken grants with their targets' boxes) and its content. A node holds the content of what its strongs reach, and the key part of each holder on a path of taken grants from one of its own actors to such a thing. A role is a function of those two inputs: the node's strongs, and grants the holders on the path took.

## What a path needs
For each edge "H holds a role on X" there is one **edge piece**: the edge write (`roles.0` on X), X's boxes to H, X's sync ID. To act on X through own actor n and holders H1..Hd a node needs the d+1 edge pieces of its path, each holder's current keyset commit, and nothing else of any holder. That is about 11 KB per holder (computed: `keys.0` 6.3 KB, the node's own boxes 2.4 to 4.3 KB, an edge piece 2.1 KB), whatever the holders' sizes and rosters. Every design below is judged by how far above that it sits.

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
- **A rotation of every thing below H, in k**: lazy (stale boxes, spec/crypto.md §4), 11.7 KB or more each, required for confidentiality (spec/requirements.md Cost: "in proportion to the rosters of what it could read"). This churn to everything below a holder on every removal is fundamental; candidates are judged against it.
- **A copy of each of those rotations' boxes to every reader of H, in k times m**: about 5.5 KB per thing below, to every member, whether or not it syncs the thing. Not fundamental: a reader of X needs its box to H from X's own rotation commit, which it opens under the epoch before; only a node entering X for the first time needs the copy.

A grant added costs nothing below H, and that must stay (notes/write-path-design.md §2, Not every actor that could write).

## Candidates
Rejected before costing: the strong stays the choice with boxes carried down the keys-open chain (the issue's option 1): it still costs A's 30 GB. Roles decide what is fetched from every grant naming the account (option 3): a stranger's grant makes the node fetch.

**(a) Key parts carried down.** Each unit carries, beside its bodies, the key part of every holder above it, as shared blobs listed under the unit's sync ID and stored once per node. A node syncing X opens only X's sync ID.

**(b) Key parts pulled.** Nothing more is listed under X. A node syncing X also syncs, for each holder on its path, that holder's sync ID restricted to role entries: the thing is **held for keys**.

**(c) A key unit per thing.** Every independent thing has two sync IDs, one for its key part and one for its sync unit; paths pull the first.

**(a) and (b) are one mechanism.** The data is the same, in the same blobs: A2's copy per (commit, thing), one blob wrapped under each sync ID that needs it (notes/write-path-design.md §2 E3), stored once per node either way. They differ in one thing only: **which sync ID's log lists the blob**. That decides who must write an entry when a holder changes (a: a writer of every unit below, k entries per change; b: nobody, the holder's own log already has it) and who can serve it (a: whoever serves X; b: whoever serves H). (c) is (b) with a second sync ID per thing: a store already tells role entries from the rest by their stamp domain, so the split hides nothing more and doubles the cost per sync ID that stage S1 works to cut (issues/many-sync-ids-cost.md).

The half of (a) that judging needs is built or planned and stays: X's sync ID carries the edge writes its held commits' paths use (A2 evidence) and the keyset commits its boxes name (spec/crypto.md §4 Carried), both functions of what X holds. What (a) would add is the boxes.

### Costs
H with m members; k independent things below it; d holders on the path; "whole" is role commits fetched as they are today, "by need" with the two baseline defects fixed (a node fetches the boxes it opens and the edge pieces of its paths: Weak spots 1). Computed from the measured sizes.

| scenario | today | (a) carried down | (b) pulled, whole | (b) pulled, by need |
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
- (a): every reader of X receives the rosters and box lists of every holder above X. Within spec/requirements.md (readers may learn who holds roles on it, directly or through other things), but far more than a judgement needs. A node keeping X unread sees one shared blob listed under every unit below a holder at the moment that holder's roster changes, and its size: which of its units share a holder, when it changes and how big it is.
- (b): a node holding H for keys learns what a reader of H learns today less its content (H's roster, which members see anyway; the things H holds). A node keeping X unread learns nothing of H. A store of H sees which peers pull role entries only (network metadata). By need, a member no longer receives the box list of every thing H holds.

### Hostile input
- Both rest on **taken grants** (notes/write-path-design.md §4, What A takes): a grant naming H counts for H's members only once a writer of H took it. A stranger's grant naming the account, or naming a holder the account acts through, is never taken, so it changes nothing a node fetches.
- (a): the node opens only sync IDs its strongs chose. A writer of X can list junk as ancestors' parts, bounded as any writer.
- (b): the node also opens the sync IDs of holders it did not name one by one. Each is on a chain of taken grants from an own actor to a thing its strongs reach, so each was chosen by the account (the first hop) or by a writer of a holder already on the path. A writer of H attaching things costs members an edge piece each (5 KB) when fetched whole, as today, and nothing by need unless a strong reaches the thing.

### Convergence
The old class (issues/roles-apart-from-syncing.md, Why roles counting over every held role commit fails) came from an edge counting because its role commit happened to be held. Under either candidate the rule is: **an edge "G holds a role on H" counts at a node only while the node holds G**, read or for keys, and the set held for keys is the least fixpoint of "an own actor, or the target of a taken grant of something held, that a chain of taken grants joins to a thing the node's strongs reach". Evidence copies and certificates that arrive for other reasons name edges whose holder is not held, so they give no role. Dropping the last strong below a holder shrinks the fixpoint: the holder is no longer held for keys, its secrets go, and the role goes with them by the one lost-access rule. This is clause 3 of notes/node-closure.md (Roles taken up) stated for every edge instead of the account's first, with "reached by a strong" replaced by "taken": the reference chooses what is held, the taken grant gives the role, so spec/requirements.md "Referencing a thing grants no rights, and removing a reference revokes none" holds as written.

### The first box
(a) fails here alone: a node that never held X cannot open X's sync ID at a store (no credential) nor the copies wrapped under it, so the piece it needs first sits where it cannot reach it. Tagging entries so that a holder's key opens them, or listing every holder thing in X's claim set with an entry box (spec/sync-ids.md §3), makes X's stores serve key material by holder, and only an admin issues steps while any writer rotates. (b) has no such gap: the node reads H by H's own box to it, and H's key part holds X's boxes to H.

## Recommendation
**(b): a thing is held for keys.** One rule, no kind of thing named in it:
- A grant gives its holder a role once taken (A5's rule, for every holder: an account, an organization, a node on its account).
- A node holds for keys every thing on a chain of taken grants from an own actor to a thing its strongs reach, and syncs that thing's sync ID for role entries only. A thing its strongs reach is held whole, as today.
- An edge counts only while its holder is held. Lost access, release and retention judge by that one role.
- The key part of H is what H's sync ID already requires beside its bodies (its role commits, its taken grants' pieces, its evidence): no new placement, no entry written anywhere when H changes, nothing added to any unit below.

Why not (a): it adds an entry under every unit below a holder for each change of the holder (the cost notes/write-path-design.md §2 already refused for rosters), puts a holder's roster-sized rotations at every store of every small thing below it, and cannot deliver the first box. Its one advantage is real and listed below (availability).

### Weak spots
1. **Still roster-sized until two baseline defects are fixed** (issues/holder-key-churn.md): every reader fetches every box of a rotation, and a holder's sync ID carries every box of every thing it holds. With them, "by need" in the table; without, a path user of a 1,000-member organization still downloads megabytes per removal, as every member does today. Fetching only the pages of boxes a node opens touches "a commit applies with all its pages" for role parts (unfetched pages are already a may-hold state, spec/sync-judgement.md §2); a node that may rotate H still needs them all.
2. **Finding a path of several hops** needs, for each holder reached, the list of what it holds (its taken grants: tid and role, tens of bytes each), since X is opaque until opened: work and bytes in the grants of the holders the account can reach, not in the path. A realm's members want that list anyway (notes/realms.md, Seeing the contents). The alternative is a path stated by whoever accepts X (as writes state theirs, A1), costing the path alone but making the role depend on a recorded path. Unmodelled either way.
3. **Availability.** A member through H served only by a node keeping X unread gets X's rotations there but not H's: it waits for any peer holding H's key part (another member, a store granted sync on H). (a) would serve it from X's stores. X already carries H's keyset commits (Carried); carrying H's boxes too is (a)'s cost again.
4. **A new way to hold a thing** in the closure walk (beside read, kept unread and on a ticket's word), in the least settled code: lost access, release, what a held thing needs, sync status per class (a node holding H for keys is no source of H's content and its "complete pass" is of role entries). It must be modelled first (held-model `closure`), with the differential's oracle.
5. **Role entries are wider than keys**: the class also holds commits carrying purge requests and blobs they link (spec/sync-ids.md §6). Either the filter takes them (small) or the class is narrowed.
6. **Taking must not be a strong.** notes/write-path-design.md §4 words an outside grant's acceptance as "a reference to X in A's unit". If that reference is a strong, taking a role on a 30 GB thing means syncing it, and the requirement on references is broken at the first hop. Taking has to be the holder's own record of the grant (a weak or ticket in its key part).

### What it replaces
To be confirmed at the design: notes/node-closure.md clauses 3 and 7 (the account's edge counting only while its target is reached), "Nothing before the strong" and a grant taken from a fire at the strong (spec/sync-inbox.md §5), the ticket-word rules that stand in for role commits a node cannot yet read (spec/sync-set.md §2 What a held ticket does, clause 8), the holder piece as a copy of X's whole `secrets.0` part, and it closes gap 2 of issues/roles-apart-from-syncing.md (Measured). A4's "members enter what A holds roles on by its boxes under A's sync ID" becomes this rule at the node's first hop: a node may hold its account for keys only, so pairing a node no longer means syncing the account's whole unit.

### With A2
One design, two halves, one blob format (the copy per (commit, thing)):
- what a reader needs to **judge** a held write rides down in the unit that holds the write (A2 evidence, a function of holdings);
- what a node needs to **act** through a holder is pulled from the holder (its key part), a function of strongs and taken grants.
The edge piece is A2's "a holder's taken grants under the holder's sync ID" (notes/redesign-plan.md A2 brief 4, taken-ness A5's), cut to the boxes to that holder.

## For Tess
1. Is "held for keys" acceptable as what syncs: a node syncing C fetches the key parts of A and B without being asked, because A's and B's own writers took the grants on its path?
2. Finding the path: by the lists of what each reachable holder holds (cost in their grants), or stated by the accept (cost in the path, role tied to the stated path)?
3. Availability (weak spot 3): accepted, as "a holder that missed key changes may be unable to read until a current holder acts for it" already is, or must X's stores be enough?
4. Taking apart from referencing (weak spot 6): the accept of a grant from outside becomes a record in the holder's key part, and the strong only chooses content. This touches the requirement held for now ("a thing is shared only by granting a role and handing over a ticket"; accepting as a strong, spec/sync-set.md §4).
5. Per-holder box fetch (weak spot 1): worth its own design now, since it decides every large roster's cost with or without this study?
