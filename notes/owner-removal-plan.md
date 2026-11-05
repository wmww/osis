# Removing owners: plan
> Summary: Build plan for replacing owners with first admins and disputes settled per node. Approved by Tess; step 3's model done. Options, model results and review findings: notes/owners.md.

## Decided (Tess)
- No owner role, no hidden owner, nothing users may want to change baked into a thing. A tid and the first admin it names stay; the first admin is history, with no power once removed.
- Admins fight: every node has a default side (first received), warns if it can, and can be overridden. Convergence is given up only there. Switching back and forth must work, may be slow.
- Accepted: a thief with an unlocked device taking control; a wrong default sealing keys to the attacker; Q (a current admin Y left in place) voiding Y's removal silently, since Y should have removed Q too; a removed node erasing and re-syncing if that turns around, with data lost if no copy is left; role history growing; a kicked admin raising a warning; the limit on new nodes (notes/owners.md).
- Recovery key: documented, not built; addable later if built.
- "Contained" means code complexity, not blast radius: a fight may do wide damage, but its handling must not spread through the code. Fix the design rather than work around oddities.

## The coherence rule
A side is an ordinary view: a node runs the ordinary rules over held data plus its trust set. No rule names the other side or asks whether a dispute is open, except the short list below. A new corner case gets fixed by adjusting that list or the design, not by a new check at the site that hit it.

Dispute-aware code, all of it:
1. **Walk** (osis-perm): trust set input and dispute detection.
2. **Trust store and API**: durable local defaults and choices, a dispute listener, choose. Synced choices are suggestions read outside the walk.
3. **Hosts and sync**: the delete check, branches and members carrying clean bodies (step 6).

Everything else reads validity as it does now. Enforced: the dispute types are private to osis-perm and the API layer, plus named exceptions; review anything else as a design failure. If step 6 needs more than a few sites, stop and redesign.

## Order
Each step passes the gate alone and is useful alone. Spec changes go with each step; spec/requirements.md Permissions, Deterministic, API and Scale change in the steps that break them.

### 0. Keys at depth 0 (issues/keys-depth0.md)
It deletes names below an actor, keyset names and the departure walk, which removes two review findings: names growing forever without snapshots, and a grant on one side leaving a holder out for good. Without it, step 1 needs a new reset point for names. Built (branch depth0); open: issues/keys-depth0-removed-member-rotates.md. Step 2 must keep the first admin's implicit edge a grant ordered at creation for key access (`rotation::members::grants` orders owners first today).

### 1. Delete roster snapshots
Delete §6, `tenures.0`, epoch starts and their rounds, `kind` 4, snapshot certificate projection, `MAX_LINKED_FRONTIERS`. Independent of owners and a pure removal. Then measure: frontier size at 10^3 and 10^4 role writes, joiner bytes, evaluation time. Frontiers that hurt can extend an earlier frontier by link. Scale requirement gets an exception for role history.

#### Step 1 measurements
`scale::role_history::cost` (osis-node, release, by hand; shapes and how to run in its header). One node writes N raw edge writes on one thing (no boxes or rotations); a joiner gets every role commit ("off", today's default: nothing writes roster snapshots on its own) or one roster snapshot written at the end ("on"). Box at load 8-35: CPU-s are up to 2x high at 10^3. Shapes: chat (1000 writers joining and leaving, 250 at 10^3), readers (same at read), devices (3 persons, about 5 admin devices each, each removal listing 10 commits; per person), invites (link edges and joiner grants; the realm grows to N/2), kicks (chat whose leaves are kicks listing 1..10^3 commits, log-uniform).

| shape, N | history off | snapshot on | frontiers total, largest | joiner ingest CPU-s off / on | evaluate anew (open) off / on | joiner peak off |
|---|---|---|---|---|---|---|
| chat 10^3 | 366 KB | 160 KB | | 11 / 4.2 | 0.09 / 0.06 s | +14 MiB |
| readers 10^3 | 366 KB | 47 KB | | 11 / 2.0 | 0.09 / 0.02 s | +13 MiB |
| devices 10^3 | 176 KB | 98 KB | 161 KB, 346 B | 1.0 / 0.4 | 0.03 / 0.02 s | +1 MiB |
| invites 10^3 | 371 KB | 183 KB | | 8.9 / 9.6 | 0.08 / 0.05 s | +16 MiB |
| kicks 10^3 | 2.1 MB | 1.9 MB | 1.7 MB, 34 KB | 10.5 / 10.7 | 0.16 / 0.13 s | +27 MiB |
| chat 10^4 | 3.6 MB | 1.4 MB (writing it 294 CPU-s) | | 109 / 194 | 1.5 / 1.0 s | +228 MiB |
| readers 10^4 | 3.6 MB | 176 KB (43 CPU-s) | | 112 / 30 | 2.4 / 0.03 s | +245 MiB |
| devices 10^4 | 1.8 MB | 1.0 MB (53 CPU-s) | 1.7 MB, 346 B | 16 / 19 | 0.32 / 0.16 s | +35 MiB |
| invites 10^4 | 3.7 MB | writing it (about 5000 holders) not done after 13 min; stopped | | 159 / - | 2.1 s | +435 MiB |
| kicks 10^4 | 25.8 MB | cannot be written: "the commit does not fit a blob" | 22.2 MB, 34 KB | 132 / - | 1.8 s | +383 MiB |

- Bytes: 364-371 B per role write, plus 34 B per commit a frontier lists. Snapshots shrink only read rosters much (20x for readers); a writer's every ended tenure and every frontier stay in the ledger forever, so with writers they save 1.1-2.6x, and a kick-heavy group at 10^4 already cannot write one.
- Time: the joiner's cost is CPU, not bytes, and it is superlinear: 10^4 role commits ingested one by one take 110-160 CPU-s (10^3: 1-11), with snapshots no better (a snapshot's per-edge deltas each join at O(roster): writing one at 10^4 took 294 CPU-s). Evaluating the timeline anew is 1.5-2.4 s at 10^4. The ingest is per-arrival timeline work (85 of 112 s for readers) and `apply: join` per `roles.0` delta: implementation, issues/role-history-join-cost.md. The owner's own edge write averaged 15-23 ms at 10^4 history (4.6 ms at 10^3), under the 50 ms budget but growing.
- 10^5 not run: the owner's writes alone would take hours here.
- Against the budgets (notes/testing.md): "node open under 1 s" and "a single local write, read or received commit under 50 ms" hold per commit; there is no join budget, but a 2-3 minute join at 10^4 role writes is past "Rare events ... under a few seconds". spec/requirements.md Scale: "No operation is O(total data) or O(history)." A join is O(role history) with or without snapshots (the ledger is), so the exception is needed either way; "State grows with the number of edits and removals ever made, a few bytes each" holds for frontiers (34 B per listed commit) but a role write is about 370 B.
- **Recommendation: the stated exception is enough; linked frontiers are not needed now.** Deleting snapshots costs at most 2.6x joiner bytes for writer groups (20x for big read rosters: 3.6 MB at 10^4 writes) and nothing in frontiers, which the ledger keeps anyway. Extending an earlier frontier by link saves only where successive frontiers overlap; in these shapes each kick lists the kicked member's own commits, disjoint, so it saves nothing. The size that hurts is about 10^4 role writes per thing (a 1000-member chat after a few thousand joins and leaves), and what hurts there is the joiner's CPU, fixed by batching the ingest, not by the spec. The one frontier that does grow without bound is a single kick of a heavy writer (notes/testing.md long aspect: `TooLarge` at 3*10^5 commits), unchanged by this step.

### 2. Owner becomes first admin
- Record: `{ first_admin, nonce }` or `{ key, nonce }`. Ownerless stops being a case: every non-key thing is one.
- Implicit edge: stands until removed, stored nowhere, so plain things stay free. For the no-key-cycles rule it is a grant ordered at the thing's creation, so it always wins; its removal may give a later keyless grant key access. Needs a removal form naming a holder with no entry (today a creation commit writes one for ownerless things).
- One authority class: delete `Class::Chain` and the rule that an edge cannot name the owner. Effective role is the path rule only.
- Secrets: derive while the first admin's edge stands and nothing else holds a role; rotation to own secrets exists. Refuse a first admin removing itself from a plain thing with no other admin.
- Rename the chain as a derivation chain where only keys use it (`[owner*]`, delete base). Rewrite `admit own`, inbox fallback, ephemeral rules, links, API `owner_of`.
- Person: a device is first admin. A recovery card is a key actor with a plain admin edge. Moving: grant then remove; update notes/moves.md.
- Remove the word: owner, ownerless and owning leave spec, code, API and CLI. Realms and tags resume once this is settled.

### 3. Disputes in the walk
Trust set as an input to `Timeline::evaluate`, D rebuilt from scratch. A trusted demotion R of X seeds D with X's writes ordered before R that R's frontier does not list, other than X's writes on its own edges. Void trusted ops lose their seeds and stay out, all at once ("shrink"). A dispute is an unapplied demotion R of X that applies as an explicit demotion once its seeds are in D; contests listing R raise none. Prompts key on (R, X). Pure function of held data and trust set. Model done (`core/test/roles-model` `trust`; notes/owners.md, Model results, committed): invites, `until` with finalizes, read and write roles, skew, actor holders and the post-owner shape hold every property. Next: osis-perm's differential against it.

Rule problems the model found:
1. **Seeds stop at R** (the prototype seeded every unlisted write of X): seeding X's later writes made a pick reject X for good, ignoring a re-grant by a third admin, and raised disputes from X's later audits. The cost: "a pick rejects the author" no longer holds. Picking the side that already wins (X's contest W ordered before R) cannot be a trust entry, since W's seeds do not reach R: the trust store (step 4) records that answer to (R, X) and hides it, rather than trusting W.
2. **Who X is** for an actor holder: the frontier rule's X (every node whose class falls) depends on the walk, so seeds would too and shrink could loop. The model uses a static set: nodes that ever reach the holder by admin edges, the demoter excluded. It over-approximates (an edge that never applied counts), so trusting a demotion that applies anyway still changes the state in 2.7% of joint tries. Harmless while trust sets hold only disputed ops; the implementation must pick one static definition and say so.
3. **Trust drops more than the audit**: R's seeds take every unlisted write of X before R, while R's own audit drops only writes of a class X fell through. A node trusting R can read less than one where R applies anyway (0.02-0.05% of edge tries). Accepted unless trust sets hold more than disputed ops.
4. Trusting both sides of one fight keeps the later-stamped one (the earlier one's seeds are empty, so its op turns void); a store never writes both, but it is the defined result.

### 4. Defaults, choices, warnings
Durable trust store per node. Default: first received, recorded at detection; a new node takes the side its own grant counts on, else host log order. On a switch, recorded defaults taken on the other side are dropped or redone (untested). A side's own party defaults to itself, as it holds its own write first. API: list disputes, listener, choose. Non-interactive nodes keep the default. CLI first, then one app warning. Devices follow their person's published choice except on a dispute about that person or the choice's author; on those each device asks.

### 5. Coming back after erasing
A removal whose frontier drops another's removal of G goes to G's inbox, like a grant. G then opens the label by its claim, or gets boxes by a rotation's inbox copy. A switch to a side that removed you is an ordinary loss; a switch back is this path.

### 6. Hosts and storage under a fork: design this before building
A dispute is a fork of an actor, and forks are permanent: two sides may live side by side for good, with devices switching sides at any time. A concession (one party's write listing the other's removal) is one more way a fork can disappear; nothing waits for one. Model: core/test/tla/sides (results table there).

**Which labels a fork reaches.** Two kinds, nothing else:
- **The forked actor's own labels** (keys from its secrets): each side rotates and registers its own step after the same point of the label's step chain.
- **Labels where someone's right flows through the forked actor**: an actor A holding a role on D whose admins fork; a person actor whose devices fork; devices added on one side after the fork. The walk judging D walks A's history and recognizes the same fork (keyed (R, X)), so every node knows which writes are fork-dependent (valid on one side only). No separate detection.

**At labels both sides use: deletes only when no side needs the body.** Without a rule, the two sides delete and re-upload forever, or one deletes a body before the other side fetched it (the shape of items 276 and 282). The rule, permanent: a node deletes a body at a host (must-not-hold or compaction) only when a reason holds on its own side and, on every other side, the body is invalid or a reason holds there too. In walk terms: no delete on the strength of a fork-dependent write unless that write is valid wherever the body is; a fork-dependent body itself goes only for such a reason. Every must-not-hold and cover reason must name its write: a purge request, the superseder that dated a death or the demotion a fall names, the covering snapshot and the deaths its cover rests on, a placement, the edge end behind `stale_card`. Uploads, local drops and fetches stay ordinary.
- **The plain rule** "never delete on the strength of a fork-dependent write, nor a fork-dependent write itself" passes every loss and loop check but keeps, forever, every version one side writes after the fork and later replaces (scenario S: side X may not delete its own superseded write, though side Y never needed it). Under a permanent fork that is all of one side's churn at those labels. The rule above fixes it with the same results elsewhere (`need` against `touch`).
- **Per field** (no deletes on a field a fork-dependent write touched): a purge both sides accept, on such a field, never reaches hosts. Under a permanent fork that is never; rejected.
- **Neutral view, the parties' own writes only, re-upload once, one-side covers ungated**: fail (loops or loss), as before.
- **Cost, permanent**: a delete only one side accepts (a purge, an old version replaced, compaction) never reaches hosts at these labels while the fork lasts.
- **Several forks**: k forks make 2^k sides. The rule stays a subset check if each fork-dependent write carries the set of fork picks its validity rests on (valid wherever the body is: the reason write's picks are a subset of the body's). Not modelled.
- **Unheld writes**: a judgment resting on a write the node does not hold (no placement held, so outside the required set) cannot be checked. It holds only because role commits go up and are fetched first; a host or relay delivering content first reopens the loss (Q0).

**The forked actor's own labels: one host branch per side.** Today a host keeps one step chain: the second side's step is refused, it replaces the label, and its new devices get only what its nodes held then (modelled: loss of reach). Instead:
- **Register gains a branch form**: a step whose parent is a step on the host's path other than the head. A registrar sends it only when its view rejects the head's step; an honest race (head valid on its view) re-registers on the head as today, so honest races never branch.
- **The host keeps every branch**, each with its own head, entries, caps and opens. A new branch starts with the entries stamped while its parent was the head: only what that step's holders could read already, no later upload. A superseded step's sync key is answered with all its children; a node follows the branch its view accepts. Label discovery ignores validity: a node reads every branch its keys open (common members, boxed by both sides, read both).
- **No thing tid changes**: labels are only sync channels.
- **Results**: pre-fork bodies at the host stay in reach of both sides for good; the step race and its loser are gone; several hosts no longer pick different winners (each gets both branches once both sides register there; not modelled).
- **The delete rule** is needed only while both sides act under the shared step: before the first one-sided step, and on the first branch until the second exists. On each branch afterwards it can be off: one side acts there (same results either way).
- **Members carry clean bodies across.** A body first uploaded after the split (a pre-fork body only a common member held, or a purge both sides accept) otherwise reaches only the uploader's branch. Common members, holding both sides' keys, also upload and delete at the branch they read but do not follow the bodies no fork-dependent write touches: the same predicate as the delete rule. With it every scenario passes except Q0.
- **Holes, stated:**
  1. Anyone who ever held a delete key of the label (an admin removed with no fork at all) can open a branch at any time; the host cannot tell. Other nodes ignore branches their view rejects. Costs: host storage within per-branch caps (as making a new label costs), and the removed admin can download again the ciphertext of entries stamped up to the step it branches from, and see which were deleted since. Nothing it could not read before (the requirements' removal limit), but a new way to get it back from an honest host. Caps per label across branches would instead let it eat the honest side's room.
  2. A host that refuses to branch: the refused side replaces the label there, as today, with the reach loss at that host; the first branch keeps the delete rule on there.
  3. After a concession nobody follows the conceded side's branch; it keeps what it held (a purge never reaches it) until deleted. Treat it as replaced: the conceding side's admins delete its content entries, as replacement does today.
- **Stuck parts**: a part sealed under an epoch a node can never open must not block the commit's other parts (spec/commits.md §4). Worth fixing generally; not about forks. Not modelled.

**Sites:** (1) one delete check where node-sync decides deletions at hosts, reading the walk's fork-dependent writes and their sides; (2) branches: send the branch form when the head's step is invalid on the own view, follow the branch the own view accepts, read every branch the keys open; (3) common members acting on clean bodies at the other branch. Hosts: the branch form of Register and the branch's starting entries.

**Problems for Tess** (question 9): the permanent host cost of one-side deletes; the rule's form (no side needs it, against the plain rule's permanent garbage); a removed admin opening a branch; the abandoned branch after a concession. Not modelled: several hosts, several forks, honest races under branching.

- From the lockout study (notes/lockout-recovery.md): a hostile admin can register a host step from its locked epochs; the recoverer accepts the step but lacks its delete key. Branch also when the head's epochs are superseded and the node lacks its delete key.

## Testing
Oracles are the design's statement of itself; change them once in the harness, not per test.
- **Alike**: same held data and same trust set read the same. The order, alike and sim oracles compare after equalizing trust sets; any other difference is a bug, as today.
- **No dispute, no effect**: with no dispute held, results equal the walk with an empty trust set, and honest sim runs without two admins removing each other raise none.
- **Switching**: for a node that dropped nothing, T then T' then T reads the same as a fresh node with those inputs. With drops: reads a subset, never invents.
- **Other things**: things outside the disputed actor's reach read the same on both sides, and nodes on different sides still sync them. Tess's requirement, and it catches a dispute check leaking outward.
- **Erase and return**: after a turned-around removal a node reads alike once a holder exists.
- **Budget**: a test or lint fails if dispute types appear outside the allowed list.
- Model: roles-model search with trust sets; `core/test/tla/roles` for shrink, plus a TLA spec for step 5 if it grows.

## Open
- Rule 4b (taint) for hidden grants: taken (Wren: an endless leak under a withholding host is worse than re-keying while it withholds; issues/keys-depth0.md). The implicit first-admin edge counts as a grant made at creation and never loses (notes/keys-requirements-study.md §4): step 2 orders implicit edges first.
- Step 6: the problems above (question 9).
- Silent rejection after a removal has been held a while, warning only the parties: optional later, needs a value that passes notes/arbitrary-values.md.
