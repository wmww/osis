# Removing owners: plan
> Summary: Build plan for replacing owners with first admins and disputes settled per node. Direction agreed with Tess, plan not yet approved, nothing built. Options, model results and review findings: notes/owners.md.

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
3. **Hosts**: at most the rules of step 6.

Everything else reads validity as it does now. Enforced: the dispute types are private to osis-perm and the API layer, plus named exceptions; review anything else as a design failure. If step 6 needs more than a few sites, stop and redesign.

## Order
Each step passes the gate alone and is useful alone. Spec changes go with each step; spec/requirements.md Permissions, Deterministic, API and Scale change in the steps that break them.

### 0. Keys at depth 0 (issues/keys-depth0.md)
It deletes names below an actor, keyset names and the departure walk, which removes two review findings: names growing forever without snapshots, and a grant on one side leaving a holder out for good. Without it, step 1 needs a new reset point for names. Build first.

### 1. Delete roster snapshots
Delete §6, `tenures.0`, epoch starts and their rounds, `kind` 4, snapshot certificate projection, `MAX_LINKED_FRONTIERS`. Independent of owners and a pure removal. Then measure: frontier size at 10^3 and 10^4 role writes, joiner bytes, evaluation time. Frontiers that hurt can extend an earlier frontier by link. Scale requirement gets an exception for role history.

### 2. Owner becomes first admin
- Record: `{ first_admin, nonce }` or `{ key, nonce }`. Ownerless stops being a case: every non-key thing is one.
- Implicit edge: stands until removed, stored nowhere, so plain things stay free. For the no-key-cycles rule it is a grant ordered at the thing's creation, so it always wins; its removal may give a later keyless grant key access. Needs a removal form naming a holder with no entry (today a creation commit writes one for ownerless things).
- One authority class: delete `Class::Chain` and the rule that an edge cannot name the owner. Effective role is the path rule only.
- Secrets: derive while the first admin's edge stands and nothing else holds a role; rotation to own secrets exists. Refuse a first admin removing itself from a plain thing with no other admin.
- Rename the chain as a derivation chain where only keys use it (`[owner*]`, delete base). Rewrite `admit own`, inbox fallback, ephemeral rules, links, API `owner_of`.
- Person: a device is first admin. A recovery card is a key actor with a plain admin edge. Moving: grant then remove; update notes/moves.md.
- Remove the word: owner, ownerless and owning leave spec, code, API and CLI. Realms and tags resume once this is settled.

### 3. Disputes in the walk
Trust set as an input to `Timeline::evaluate`, D rebuilt from scratch. A trusted demotion T seeds D with its victim's unlisted writes. Void T lose their seeds and stay out, all at once ("shrink"). A dispute is a demotion R of X voided by X's unlisted write; contests listing R raise none. Prompts key on (R, X). Pure function of held data and trust set. Extend roles-model and the differential first, covering what the prototype did not: invites, `until`, other roles, clock skew. The prototype patch is one input, if kept.

### 4. Defaults, choices, warnings
Durable trust store per node. Default: first received, recorded at detection; a new node takes the side its own grant counts on, else host log order. On a switch, recorded defaults taken on the other side are dropped or redone (untested). A side's own party defaults to itself, as it holds its own write first. API: list disputes, listener, choose. Non-interactive nodes keep the default. CLI first, then one app warning. Devices follow their person's published choice except on a dispute about that person or the choice's author; on those each device asks.

### 5. Coming back after erasing
A removal whose frontier drops another's removal of G goes to G's inbox, like a grant. G then opens the label by its claim, or gets boxes by a rotation's inbox copy. A switch to a side that removed you is an ordinary loss; a switch back is this path.

### 6. Hosts and storage: design this before building
Goal: the fewest sites. Settled by a model (core/test/tla/sides, results table there) unless marked:
- **Fork of an actor means fork of its labels.** A node refused a step on an actor with its own epochs replaces the label by the existing flow, keys from its side's secrets. No stamping under a captured head.
- **Label discovery ignores validity**: read every label named by a possible admin's `label.0` that the node's keys open, so common members still reach both.
- **Stuck parts**: a part sealed under an epoch a node can never open must not block the commit's other parts (spec/commits.md §4). Worth fixing generally; it is not about disputes. Not modeled.

**Where loops come from.** Each side runs today's rules over its own validity. At every label both sides act at, which is every label where a disputed party or a device it added since writes, not only A's own, a body one side judges must-not-hold and the other must-hold is deleted and uploaded again forever (the shape of items 276 and 282). Worse, when the deleting side gets there before any node of the other side fetched the body, it is gone.

**Candidates, as modeled:**
- **(a) Gate deletes at hosts: holds, in the right form.** Dd is the set of writes valid on one side only: the closure of both parties' unlisted writes, which the walk can export (step 3). A node never judges a disputed write without both removals (a write is pending until its author's chain arrives, and that chain carries the other party's removal), so it never misses a held one.
  - Per reason: no delete at a host of a body that is itself in Dd, or for a reason whose write is in Dd. Passes every scenario, same as the two-walk oracle "must-not-hold on both sides". Every must-not-hold and cover reason must name its write: a purge request, the superseder that dated a death or the demotion a fall names, the covering snapshot and the deaths its cover judgment rests on, a placement, the edge end behind `stale_card`. Many sites.
  - Per aspect: no delete at a host of a body on an aspect holding a Dd write, or named by a Dd purge, placement or edge end. Passes everything but promptness: a purge both sides accept, on an aspect a disputed write touched, never reaches the host (the aspect stays touched while the dispute is held, for good).
  - Gating the parties' own writes only fails: a device X added after the dispute supersedes a body; that write is no party's but is valid on side X only, so the loop and the loss stay.
  - Gating by a neutral view (judge again with every disputed write void) fails where must-not-hold rests on a write being invalid: X's post-dispute write under keep at most 0 falls on side Y, the neutral view agrees with Y, and the loop stays; likewise a placement only side Y has.
- **(b) Re-upload once, then keep it local: fails.** The loop ends, but the body then lives only at the keeping side's existing holders: fresh nodes of that side never get it, and it is lost when those holders go. It also undoes today's healing of a stale or hostile delete (a removed writer deleting twice wins).
- **(c) Fork: needed for keys, no fix for loops, and it splits reach.** The loser deletes nothing at L (it does not control L's head, as in today's replacement flow). Until the step race ends both sides act at L, and today's rules lose bodies in that window; with (a) they do not. After it, the losing side's new devices read only its replacement label, which holds what the losing side's nodes held at the race. A body left only at L and with the winner's nodes is out of their reach, and a purge both sides accept known only to one side never reaches the other side's label. Members uploading clean bodies (no Dd write on them) to the label they read but do not act at fix the undisputed part; disputed bodies stay out of reach.
- **(d) One-side covers accepted: fails.** No loop (compaction deletes once per body per node), but loss: side X compacts a body under its own snapshot, the member on X drops it, and side Y never fetched it. Covers go through the gate like any delete; bodies covered only by one side's snapshots stay at hosts.
- **Unheld writes** (not a candidate): a judgment resting on a write the node does not hold (no placement held, so outside the required set) cannot be gated. It holds only because role commits go up and are fetched first; a host or relay delivering content before the placement reopens the loss.

**Fewest dispute-aware host and sync sites that work:** (1) one gate where node-sync decides deletions at hosts (must-not-hold and compaction), reading Dd, per aspect or per reason; (2) the fork as above: act at a label only under keys from commits valid on the own side (ordinary), replace on a refused step, read every label the node's keys open; (3) optionally, members carrying clean bodies across the fork. Uploads, local drops and fetches stay ordinary.

**Problems for Tess:**
1. Purges, supersedes and covers that only one side accepts never reach hosts while the dispute is held: the ciphertext stays and hosts grow. The per-aspect gate extends this to purges both sides accept, on aspects a disputed write touched.
2. Per reason is precise but touches every must-not-hold reason; per aspect is one check plus three cross-aspect reasons. Pick one.
3. The fork splits reach: the losing side's new devices get what its nodes held at the race, plus what members carry.
4. Not modeled: several hosts with different race winners (both sides would be refused somewhere and both replace L), several disputes, keep-at-least and `nobody`.

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
- Step 6: problems 1-4 above (question 9).
- Silent rejection after a removal has been held a while, warning only the parties: optional later, needs a value that passes notes/arbitrary-values.md.
