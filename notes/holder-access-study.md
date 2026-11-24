# Acting through holders without their content
> Summary: How a node acts on a thing through holders it does not sync whole (Tess): grants belong to the thing granted and sync with it; references decide what a node syncs; a grant from outside reaches its holder as an offer (the bootstrap: the thing, its sync ID, the holder's boxes), never as proof; a node's role is by the grants of what it syncs; keys are found from a synced thing up (the holders its grants name, held for keys: role entries alone). With the measured baseline, what a path needs, why the search down from the account was dropped, the model and the joint property with held-model `evidence`.

**Principle: grants belong to the thing granted.** A thing's grants are its own data and sync with it. What a node syncs comes from its strongs alone: a reference is how a node finds what it cares about. A role decides only what the node may do with what it syncs, and which holders' key parts it fetches to do it.

## The direction
The flow of a grant from outside: the `grant@~0` signal, a reference, ordinary sync, permissions.
1. **A grant from outside is an offer** (spec/sync-inbox.md §5). Its fire carries what the app needs to add a reference and the node needs to start syncing the thing: the thing, its sync ID, the holder's boxes (as built: the role commit's copy on the target with its evidence, which is how the engine judges a box before the target syncs). It is kept as the holder's setting keeps the signal (`INBOX_LIFETIME` on an account's inbox) and proves nothing: disabling the signal or the fire leaving breaks no grant, role, key or sync step.
2. **The role is by the thing's grants as synced** (spec/sync-set.md §2 Own actors): once the thing syncs everything is ordinary. No list of grants is kept with the holder, no grant is "taken", no fire is kept as proof, and nothing accepts a grant.
3. **Keys are found from the synced thing up** (spec/sync-set.md §2 Held for keys). For a thing the node closure reads, the holders its grants name, and those the grants of such a holder name in turn, up to the node's own actors: each one the node opens and does not read is held for keys (its key part pulled from its own sync ID by role entries alone, spec/sync-ids.md §6). Every path, not only the one a write picks (core picks per write: the shortest path giving the needed role, `engine/write.rs` `role_path`/`path_with`), so a revoked path never leaves a thing unwritable while another is fetched.
4. **Own boxes only.** A node fetches only the boxes it opens, never a holder's whole box set (issues/holder-key-churn.md). Any node holding a holder's key part can serve it.
5. **Availability gap accepted.** A node whose only reachable sources keep C unread and hold no key part of A or B gets no key change of A there. A store meant to serve C to people acting through A keeps A's and B's key parts too: the user's or app's configuration, no new mechanism.

**Why not down from the account.** A rejected direction kept every grant a holder "takes" under the holder's sync ID and searched down from the account's grants. It needed a judgement of which grants count that only the holder's readers could make (takenness: a path stated to the holder, or a held fire while the setting enabled it), fires kept as proof with rules for which fire of an edge to keep, a replay hole once a fire's edge had ended and its fire gone, and a standing read of every holder reached to find the paths. All of it follows from asking the holder what it holds; asking the thing dissolves it. A fresh session should not reach for a grant list on the holder: the key part's edge pieces (below) are a bootstrap for siblings, a function of what a node holds, and decide nothing.

## What a path needs
For each edge "H holds a role on X" there is one **edge piece**: the edge write (`roles.0` on X), X's boxes to H, X's sync ID. To act on X through own actor n and holders H1..Hd a node needs the d+1 edge pieces of its path, each holder's current keyset commit, and nothing else of any holder. That is about 11 KB per holder (computed: `keys.0` 6.3 KB, the node's own boxes 2.4 to 4.3 KB, an edge piece 2.1 KB), whatever the holders' sizes and rosters.

X's own sync ID cannot give a first box: its role commits are wrapped under X's secrets. The first box comes from the offer, or from H's key part (spec/permissions.md §4 Key part): a node syncing both H and X logs H's edge piece on X under H's sync ID, stamped where it may write H, so the account's other nodes, and H's other readers, start syncing X without the offer. A node reaching X by a strong with no offer and no node of its holder syncing X holds nothing of X.

## Baseline: what already churns
Measured in the engine (the commits of `grant`, `demote` and `ensure_rotated` packaged as `thing_cost::what_a_reader_costs` packages its grant: holder H with m writer members, H write on X, X's roster its admin and H; sync entries and stamps not counted), with notes/thing-cost.md:

| event | bytes | who downloads it |
|---|---|---|
| a member granted on H (read) | one commit, 4.0 KB | every reader of H; nothing below H |
| H granted write on X (granter holds H's secret: symmetric boxes) | one commit, 2.1 KB (`secrets.0` 1.15 KB) | X's syncers; copied under H's sync ID for every reader of H |
| a member removed from H | H's rotation: 2.7 KB + 4.9 KB per remaining writer (12.5 KB at 2 holders, 32.2 KB at 6; a reader's boxes are 2.7 KB) | every reader of H, every box of it (a commit applies only with all its pages, spec/crdt.md §8) |
| then each independent X that H holds a role on | X's rotation when next written, 11.7 KB + boxes of X's other holders (about 21 KB seen by a document's reader) | X's syncers; and its whole `secrets.0` part (5.0 KB here, every box of X) plus `sync.0` is copied under H's sync ID for every reader of H (engine `key_part`) |
| H's content changes | the change | every syncer of H's sync ID, path users included |

So with m members and k independent things below H, one removal costs, by design and before any change here:
- **H's rotation, in m**: 52 KB at 10 members, 4.9 MB at 1,000 (2.7 MB if they only read), downloaded by each member: m times that across the network. 100,000 direct members cannot exist (`MAX_CLAIMS` 65,536); nested three deep at fan-out 47 a removal costs every member the top rotation (about 230 KB), and the members of the two holders below it theirs.
- **A rotation of every thing below H, in k**: lazy (stale boxes, spec/crypto.md §4), 11.7 KB or more each, required for confidentiality (spec/requirements.md Cost: "in proportion to the rosters of what it could read"). Fundamental; candidates are judged against it.
- **A copy of each of those rotations' boxes to every reader of H, in k times m**: about 5.5 KB per thing below, to every member, whether or not it syncs the thing. Not fundamental: a reader of X needs its box to H from X's own rotation commit, which it opens under the epoch before; only a node entering X for the first time needs the copy, and only the boxes to H (own boxes, direction 4).

A grant added costs nothing below H, and that must stay (notes/write-path-design.md §2, Not every actor that could write).

## With A2
One design, two halves, one blob format (the copy per (commit, thing)):
- what a reader needs to **judge** a held write rides down in the unit that holds the write (evidence, a function of holdings);
- what a node needs to **act** through a holder is pulled from the holder (its key part, own boxes), found from the synced thing up.

## The model
held-model `closure::keys` (core/test/held-model/src/closure/keys.rs, tests/it/spec_holders.rs): `for_keys` is the walk up from the things a node closure reads through the holders their grants name, taking each one the node's roles read; its oracle is every holder on a keyed path of read hops from an own actor to a read thing (`on_paths`), and the two agree on every small world and on random ones, so the walk up finds every path the node can act along and nothing off them. The sync differential's `Model::closure` (core/sync/tests/it/harness/history.rs) is `hc::closure`: own actors' roles over the world's grants.

**The joint property** (`World::joint`, over held-model `evidence` worlds under the design's delivery, `Stage::A2`): a node acting as a signer and holding one sync ID S plus its paths' key parts (each holder's on a path from the signer to a thing of S's unit: that holder's sync ID's role entries as logged; the signer's own: every edge write naming it or on it, with their evidence) judges and acts as the node holding everything:
- `J-judge`: each body S should carry that it holds, it judges as S's reference or as the node holding everything;
- `J-act`: a content write it would make on a thing of S's unit, along any path the world's roles or its own reading run, it judges valid iff the node holding everything does;
- `J-logged`: one it judges valid, logged under S with what its view requires there, S's reader judges as the node holding everything.

Over 3,164 worlds (every 13th family world, 400 random, 400 wide; `joint_one_sync_id_and_key_parts_act_as_everything_plain` at `OSIS_JOINT_STEP=13 OSIS_JOINT_RANDOM=400`, about 70 s wall) the design fails none. Controls: the sync ID alone fails `J-act` (2,514 worlds: a write pending for want of a hop's grant, or valid by a removal it lacks) and `J-logged` (191: its reader shows a removed member's write, the gap); logging its write with what S's entries alone require fails `J-logged` (2,462: the path's grants missing); key parts without their removals fail `J-act` (2,254: it acts along a removed hop; default test `joint_a_removed_hop_reaches_the_actor_through_the_key_part`). `J-judge` has no control: no generated world holds a key part that moves a verdict on S's bodies off both S's reference and the node holding everything. Found on the way: the key part carries what lazy delivery leaves out of S for the actor's own writes (the signer's removal is in its own part, direction 2), so a node that acts closes the gap for what it writes, as D1 says.


**Not modelled**: delete keys (issues/delete-key-levels-unchecked.md); own boxes against "a commit applies with all its pages"; an offer's keep and what a node holds of a thing before it syncs it.
