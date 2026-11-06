# Removing owners: plan
> Summary: Plan for replacing owners with first admins and settling admin disputes per node, approved by Tess. Steps 0 (keys at depth 0), 1 (no roster snapshots) and 3 (disputes in the walk: osis-perm takes a trust set) are built; step 2 (owner becomes first admin) is built in meaning (stages A and B of issues/owner-to-first-admin.md), its renames (C) and API (D) pending; step 4 (defaults) is what makes a node take a side, so the backdating hole stays open in practice until it is built; step 6 (hosts under a fork) is model-checked. Reasoning, options and model results: notes/owners.md.

## Decided (Tess)
- No owner role, no hidden owner, nothing users may want to change baked into a thing. A tid and the first admin it names stay; the first admin is history, with no power once removed.
- Admins fight: every node has a default side (first received), warns if it can, and can be overridden. Convergence is given up only there. Switching back and forth must work and may be slow.
- Accepted: a thief with an unlocked device taking control; a wrong default sealing keys to the attacker; a current admin Q that Y left in place voiding Y's removal silently (Y should have removed Q too); a removed node erasing and re-syncing if that turns around, with data lost if no copy is left; role history growing; a kicked admin raising a warning; the limit on new nodes (notes/owners.md).
- Recovery key: documented, not built; addable later.
- "Contained" means code complexity, not blast radius: a fight may do wide damage, but its handling must not spread through the code. Fix the design rather than work around oddities.

## The coherence rule
A side is an ordinary view: a node runs the ordinary rules over held data plus its trust set. No rule names the other side or asks whether a dispute is open, except in this list:
1. **Walk** (osis-perm): trust set input and dispute detection.
2. **Trust store and API**: durable local defaults and choices, a dispute listener, choose. Synced choices are suggestions read outside the walk.
3. **Hosts and sync**: the delete check, branches, members carrying clean bodies (step 6).

Everything else reads validity as it does now. The dispute types are private to osis-perm and the API layer plus named exceptions; anything else using them is a design failure. If step 6 needs more than a few sites, stop and redesign. A new corner case is fixed by adjusting this list or the design, not by a check at the site that hit it.

## Steps
Each step passes the gate alone and is useful alone; spec changes go with it, and spec/requirements.md Permissions, Deterministic, API and Scale change in the steps that break them.

### 0. Keys at depth 0: built
A group never looks inside its member actors (notes/crypto.md, Holder actors at depth 0). Open: issues/keys-depth0-removed-member-rotates.md.

### 1. No roster snapshots: built
Every role commit stays and a joiner judges all of it (spec/requirements.md Scale states the exception); every commit carries one delta per aspect. Why and the measured cost: notes/permissions.md, Role history. Open: issues/role-history-join-cost.md (the slow join), issues/rotation-names-grow.md (history boxes name every departure ever).

### 2. Owner becomes first admin
Stages: issues/owner-to-first-admin.md (A and B built: one record form, one authority class; C the words in spec and code; D API and CLI, overlapping issues/api-after-owners.md).
- **Built**: every thing's record names its first admin (`{ admin, nonce }`; a key actor's `{ key, nonce }`); the record edge is in force from the start, stored nowhere (virtual in osis-perm: read from the record unless a write set or removed it), removable like any edge, its removal resetting an entry of its own delta; one authority class (edge admin by any path, or an invite level); a plain thing derives its secrets from its first admin's; the record chain carries derivation, labels, inboxes and certificates through standing record edges; an account's first admin is the node that made it, its recovery key an admin by a plain edge; a link's K has the sharer's actor as first admin; lowering the last admin edge of a plain thing is refused (signed anyway: a stated limit). Details: notes/permissions.md (First admins), notes/crypto.md.
- For the no-key-cycles rule the record edge is a grant ordered at the thing's creation, so it always wins; its removal may give a later keyless grant key access (a re-seal, as a new grant; spec/crypto.md §4 Key access, modelled `D0_fa_*`).
- Consequence of one class (accepted, as "a current admin Q that Y left in place"): an admin's self-grant on a thing below survives its removal above until an admin removes that edge too; the walk audits only where a class falls. On a node trusting the removal the self-grant is a seed and drops (step 3).
- Secrets: a derived epoch someone wrote under should count as a current epoch of the thing, so its writer merges the thing (modelled, not built: issues/derived-write-merge.md; spec/crypto.md §4 Current states the limit meanwhile).
- Pending (C, D): the words owner, ownerless and owning leave spec, code, API and CLI (`[owner*]`, `MAX_OWNER_DEPTH`, `owner_chain`, `Owner`, `create_owned_by`, `create_ownerless`, `owner_of`, the CLI `ownerless`). Realms and tags resume once this settles.

### 3. Disputes in the walk: built
osis-perm `trust.rs`; the rule is spec/permissions.md §5.1, Trust set. The trust set (`Trust`: a set of `WriteId`s) is an input to `Timeline::evaluate_with` and a field of `Timelines` (`set_trust`), D rebuilt from scratch. A trusted demotion R of holder M seeds D with the unlisted writes ordered before R by M's possible admins (static: nodes that ever reach M by admin edges, the demoter excepted) on what R puts in question (R's target and what it ever reaches), except a node's write lowering its own edge (a self-removal never contests R; a self-grant does and drops). Void trusted ops lose their seeds, all at once. A dispute (`Timeline::disputes`, keyed (R, M)) is a trustable op the settled walk left unapplied and no seed dropped, that applies as an explicit write lowering M's edge once its seeds are in D. A pure function of held data and trust set; model-checked (notes/owners.md, Model results) and differential-tested (`differential::trust_model_agrees`, tier 1 and `_large`; `scenarios::*_spec_permissions_5_1` for the backdating hole, seeds, limits, from-scratch evaluation).
- **Default**: `Timelines` start with an empty trust set and the engine never sets one, so every node reads as the plain walk. The backdating hole (issues/ownerless-first-admin-backdate.md) therefore stays open in practice until step 4 records a default side at detection: the walk can take a side, nothing yet tells it to.
- **Cost**: a component holding a trusted op is only ever evaluated from scratch (`extend`, `append` and `add_leaves` decline it; never saved or restored), one walk per held-set change (0.3-0.5 s at 10^4 edge writes); the trust set's seeds and void ops read the whole held set, so continuing a walk would need its own correctness argument. Disputes cost one extra walk per unapplied trustable op with seeds (none in honest histories, but a removed admin can sign any number: issues/dispute-scan-cost.md, to bound before step 4 asks at detection), computed on demand and memoized per timeline. With an empty trust set nothing changes: perm `bench` +0.001% instructions, node `scale::role_change_and_open_cost` within noise (-0.4%).
- **Rule choices** (each model-checked):
  1. **Seeds stop at R**, so a choice no longer rejects its author for good: X's later writes after a re-grant by a third admin count. Choosing the side that already wins (X's contest W ordered before R) cannot be a trust entry (W's seeds do not reach R): the trust store (step 4) records that answer to (R, M) and hides the dispute instead of trusting W.
  2. **Who R demotes** is the static set above (over-approximate: read members cannot contest). So trusting a demotion that applies anyway still changes the state in about 2.8% of joint tries and 0.03-0.2% of edge tries: harmless while trust sets hold only disputed ops.
  3. **Trust drops more than the audit**: R's seeds take every unlisted write of X before R on what R puts in question, while R's own audit drops only writes of a class X fell through; a node trusting R can read less than one where R applies anyway. Accepted unless trust sets hold more than disputed ops.
  4. **Both sides of one fight trusted** keeps the later-stamped one (the earlier's seeds are empty, so its op turns void); the void op has no seeds, so it is rejected, not disputed. A store never writes both; that is the defined result.
  5. **Demoting** means the explicit write's value is below the edge's value just before it (not the edge as restored): the one reading the three models and osis-perm share exactly; an explicit write on an already-removed edge (finalizing a self-removal) raises no dispute.

### 4. Defaults, choices, warnings
A durable trust store per node. Default: first received, recorded at detection; a new node takes the side its own grant counts on, else host log order. On a switch, defaults recorded on the other side are dropped or redone (untested). A side's own party defaults to itself, as it holds its own write first. API: list disputes, a listener, choose. Non-interactive nodes keep the default. CLI first, then one app warning. Nodes follow their account's published choice except on a dispute about that account or the choice's author; there each node asks.

### 5. Coming back after erasing
A removal whose frontier drops another's removal of G goes to G's inbox, like a grant. G then opens the label by its claim, or gets boxes by a rotation's inbox copy. A switch to a side that removed you is an ordinary loss; a switch back is this path.

### 6. Hosts and storage under a fork (design before building)
A dispute is a fork of an actor, and forks are permanent: two sides may live side by side for good, nodes switching at any time. A concession (one party's write listing the other's removal) is one more way a fork can end; nothing waits for one. Tess on this design (Q9): "if that actually works great". Model: core/test/tla/sides (results table there).

**Which labels a fork reaches**, two kinds only:
- **The forked actor's own labels** (keys from its secrets): each side rotates and registers its own step after the same point of the step chain.
- **Labels where a right flows through the forked actor** (an actor A holding a role on D whose admins fork; an account whose nodes fork; nodes added on one side): the walk judging D walks A's history and recognizes the same fork by (R, X), so every node knows which writes are fork-dependent (valid on one side only). No separate detection.

**At labels both sides use, delete only when no side needs the body.** Without a rule the sides delete and re-upload forever, or one deletes a body before the other side fetched it. The rule, permanent: a node deletes a body at a host (must-not-hold or compaction) only when a reason holds on its own side and, on every other side, the body is invalid or a reason holds there too. In walk terms: no delete on the strength of a fork-dependent write unless that write is valid wherever the body is; a fork-dependent body goes only for such a reason. So every must-not-hold and cover reason names its write: a purge request, the superseder that dated a death or the demotion a fall names, the covering snapshot and the deaths its cover rests on, a membership write, the edge end behind `stale_card`. Uploads, local drops and fetches stay ordinary.
- Rejected: **the plain rule** (never delete on the strength of a fork-dependent write, nor a fork-dependent write itself) passes every loss and loop check but keeps forever every version one side writes and later replaces (side X may not delete its own superseded write though side Y never needed it): all of one side's churn at those labels. **Per field** (no deletes on a field a fork-dependent write touched): a purge both sides accept never reaches hosts. **Neutral view, the parties' own writes only, re-upload once, one-side covers ungated**: loops or loss.
- **Cost, permanent**: a delete only one side accepts (a purge, an old version replaced, compaction) never reaches hosts at these labels while the fork lasts.
- **Several forks**: k forks make 2^k sides. The rule stays a subset check if each fork-dependent write carries the set of fork picks its validity rests on (a reason write's picks a subset of the body's). Not modelled.
- **Unheld writes**: a judgment resting on a write the node does not hold cannot be checked. It holds only because role commits go up and are fetched first; a host or relay delivering content first reopens the loss (Q0 in the model).

**The forked actor's own labels: one host branch per side.** With one step chain per host, the second side's step is refused, it replaces the label, and its new nodes get only what its nodes held then (modelled: loss of reach). Instead:
- **Register gains a branch form**: a step whose parent is a step on the host's path other than the head. A registrar sends it only when its view rejects the head's step; an honest race (head valid in its view) re-registers on the head, so honest races never branch. Also branch, from the newest path step whose delete key the registrar holds, when the head's step registers epochs the registrar's current epochs supersede and it lacks the head's delete key: a hostile admin that rotated to itself and registered (notes/lockout-recovery.md, Disputes).
- **The host keeps every branch**, each with its own head, entries, caps and opens. A new branch starts with the entries stamped while its parent was the head: only what that step's holders could already read. A superseded step's sync key is answered with all its children; a node follows the branch its view accepts. Label discovery ignores validity: a node reads every branch its keys open.
- **No thing tid changes**: labels are only sync channels.
- **Results**: pre-fork bodies at the host stay in reach of both sides; the step race and its loser are gone; several hosts no longer pick different winners (each gets both branches; not modelled).
- **The delete rule** is needed only while both sides act under the shared step: before the first one-sided step, and on the first branch until the second exists. On each branch afterwards it can be off.
- **Members carry clean bodies across.** A body first uploaded after the split otherwise reaches only the uploader's branch. Common members, holding both sides' keys, also upload and delete at the branch they read but do not follow the bodies no fork-dependent write touches (the delete rule's predicate). With it every scenario passes except Q0.
- **Holes, stated:**
  1. Anyone who ever held a delete key of the label (an admin removed with no fork at all) can open a branch at any time; the host cannot tell. Others ignore branches their view rejects. Costs: host storage within per-branch caps, and the removed admin can download again the ciphertext of entries stamped up to the step it branches from, and see which were deleted since: nothing it could not read before (the requirements' removal limit), but a new way to get it back from an honest host. Caps per label across branches would instead let it eat the honest side's room.
  2. A host that refuses to branch: the refused side replaces the label there, with the reach loss at that host; the first branch keeps the delete rule on there.
  3. After a concession nobody follows the conceded side's branch; it keeps what it held until deleted. Treated as replaced: the conceding side's admins delete its content entries.
- **Stuck parts**: a part sealed under an epoch a node can never open must not block the commit's other parts (spec/commits.md §4). Worth fixing generally; not modelled.

**Sites**: (1) one delete check where node-sync decides deletions at hosts, reading the walk's fork-dependent writes and their sides; (2) branches: send the branch form, follow the branch the own view accepts, read every branch the keys open; (3) common members acting on clean bodies at the other branch. Hosts: the branch form of Register and a branch's starting entries. Not modelled: several hosts, several forks, honest races under branching.

## Testing
Oracles are the design's statement of itself; change them once in the harness, not per test.
- **Alike**: same held data and same trust set read the same. The order, alike and sim oracles compare after equalizing trust sets; any other difference is a bug.
- **No dispute, no effect**: with no dispute held, results equal the walk with an empty trust set; honest sim runs without two admins removing each other raise none.
- **Switching**: for a node that dropped nothing, T then T' then T reads as a fresh node with those inputs. With drops: reads a subset, never invents.
- **Other things**: things outside the disputed actor's reach read the same on both sides, and nodes on different sides still sync them (Tess's requirement; catches a dispute check leaking outward).
- **Erase and return**: after a turned-around removal a node reads alike once a holder exists.
- **Budget**: tools/policy.py fails if `osis_perm::{Trust, Dispute, trust}` or the queries `set_trust`, `disputes`, `evaluate_with`, `trusted_active` are called outside core/perm and core/osis (by name, whatever the receiver).
- Models: roles-model search with trust sets; `core/test/tla/roles` for shrink, plus a TLA spec for step 5 if it grows.

## Open
- Step 6 holes above.
- Silent rejection after a removal has been held a while, warning only the parties: optional later; needs a value that passes notes/arbitrary-values.md.
