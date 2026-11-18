# Full-size sync differential: open failure classes
> Summary: `OSIS_FULL=1 differential::histories_hold_their_closure` over seeds 0..199 fails 5 (131, 138, 169, 180, 189). A reader lacking a keying commit its holder logs (189) has a shrunk script; chain reads (138, 169), a keyless read (180) and 131 are unstudied.
> Priority: normal
> Tags: sync, engine, tests

Seed numbers move whenever commit bytes change (worlds are seeded by ID): work from scripts, and turn each class into a hand test (notes/principles.md, Never pin a seed). Replay: `OSIS_FULL=1 OSIS_SYNC_SEED=<n> OSIS_SYNC_SEEDS=1`. Run the 200 seeds as four `tools/heavy` holds of 50 (about 4 minutes each on an idle box).

## A reader lacking a keying commit its holder logs (189)
- Shrunk script on world 189 (debugging aid, 8 steps): `New(3), NewIn(3, 0), Give(3, 1, Holder::Node(1), Syncs), Strong(1, None, 1), Strong(1, None, 0), Give(3, 0, Holder::Node(1), Reads), Run, Unstrong(0, Some(0), 1)`. Node 1 holds, as must-hold under T0's sync ID, a role commit (`keys.0`, `sync.0`, `secrets.0`) on T1 by node 3, with `kept: true`; node 0, caught up, has no entry of it at all. Not studied further.
- Ruled out: the history path. A grant with history writes the history entry of each epoch it boxes (`osis_keys::box_holder`), a plain thing's derived epochs from before its keying included, and boxes the holder up to the grant's own role (spec/crypto.md §4 Key access). No keyless grant or raise is in this script.

## Reads the model rejects
- 138, 169: the node reads by its role commits through a chain path (a grant to a thing, then record edges) that held-model's closure does not count.
- 180: the node reads a value while holding no secret of the thing, through a keyless grant chain (`None with key access`).
- 131: a node reads a thing unlike the reference.
- None studied: first decide whether the model or the engine is right in each. Shrinks of these stop at the 150-candidate cap at 20 to 50 steps.

## Latent, no reproducer on main
- A departed store on a live connection may never be reopened to be moved past its keys: on `keel-diff-200-wip` (store holding older epochs' secrets), the script `New(1), Give(1, 0, Holder::Node(0), Syncs), Give(1, 0, Holder::Node(2), Writes), Strong(2, None, 0), Run, Strong(0, None, 0), Run, Revoke(1, 0, Holder::Node(0))` left node 0 keeping T's entries on 80 of 80 worlds (on main 0 of 80). The readers' members at the stores (nodes 0 and 3) ended and closed when genesis, registered there, became their step; after the revocation nothing reopens S: the stores' credentials and `changed_at(S)` do not move, so they never test S again (spec/sync-opens.md §5 Testing), and a reader tests nothing toward a peer it judges departed (no walk state, §4), though its filter now shows the sync proofs the stores would hit. So `inbox::register` has no member to plan on.

## Stale status sources after a power cycle
- Not reached by seeds 0..199. `Node::closed` returns early only when it holds no session for the connection; a session goes only in `closed` itself, which then closes it in streams and opens and hands its members on, and opens learns of a connection only through its session's messages. So that early return skips nothing, and the stale path is elsewhere; no reproducer, so no hand test.
