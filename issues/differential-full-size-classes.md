# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size (25 of 200 seeds failing on 339ddd951, eight classes by first panic, three with shrunk scripts) and the three small-size seeds tools/known_failures.txt lists: each class to turn into a hand-written test.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes change: work from scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; run the 200 as four `tools/heavy` holds of 50 (about 1,450 CPU-s and 130-230 s wall each). A script replays in a scratch test in `differential.rs` (`holds_on(0, 3, 4, &script, String::new(), false)`, full size); `OSIS_SYNC_SHRINK=1` shrinks a seed.

## Full size, on 339ddd951
25 of 200 fail, none hang, none storm. By first panic:

- **Reads unlike the reference** (15, 23, 52, 53, 102, 134). Seed 15's script, diagnosed as an oracle gap (the engine is right): `New(1), Give(1, 0, Holder::Public, Syncs), Give(1, 0, Holder::Node(2), Reads), Unstrong(1, None, 0), Strong(2, None, 0)`. Node 1 releases thing 0 before any run, so its grant to the public goes with it (spec/sync-set.md §3 Nothing of R stays); the grant to node 2's account reaches it as an offer. The reference, handed every commit, counts the public's grant among the roles. The oracle excuses lost value writes only (`lost_writes`); a lost role write changes the roster, so the reference and the model need building without it, but a lost commit can be the parent of one that survived as an offered piece. The other seeds unshrunk.
- **Sync set Read, the model Unread** (12, 19, 31, 68, 84, 85, 149). Seed 31's script, a removed writer kept unread by the public's sync alone: `New(2), Give(2, 0, Holder::Node(0), Writes), Give(2, 0, Holder::Public, Syncs), Strong(3, None, 0), Revoke(2, 0, Holder::Node(0))` (at `holds_on(0, 2, 3, ..)`: `New(1), Give(1, 0, Holder::Node(0), Writes), Give(1, 0, Holder::Public, Syncs), Strong(0, None, 0), Revoke(1, 0, Holder::Node(0))`). The public holds sync alone, so the model keeps the thing unread at every node a strong reaches; node 0, its account removed, holds no sync secret and follows the thing by the public entry, which opens nothing while the public does not read. Open question: how a party with no role but the public's sync takes the public's sync box (the public pieces its account's unit carries, spec/sync-set.md §2, or the public entry listed at sync too). The other seeds unshrunk.
- **Sync set None, the model Keys** (10, 38, 78, 151). Seed 10's script is issues/chain-top-unseen-by-sync-holder.md's (a tess-call). A second script, undiagnosed, fails alike with every sync-alone holder sent each step bearing its sync key, so it has another cause: `New(0), New(2), New(2), New(1), Give(2, 1, Holder::Node(1), Reads), Strong(1, Some(3), 2), Give(2, 2, Holder::Thing(1), Reads)` ("node 1's sync set holds thing 1 as None, the model Some(Keys)").
- **Sync set Unread, the model Read** (43, 162, 167): unshrunk.
- **Sync set None, the model Read** (65) and **Read, the model None** (39): unshrunk.
- **Must-hold bodies a caught-up reader lacks** (128, 174): unshrunk.
- **Must-hold bodies with no entry at quiet** (35). Script, undiagnosed: `New(0), Pair(3), Run, Give(4, 0, Holder::Node(1), Syncs), Give(3, 0, Holder::Node(1), Reads), Partition(3, 4), Inbox(4, Some(0)), Partition(3, 0), Run`: concurrent grants by two nodes of one account across a partition, an inbox move between.

## Small size
tools/known_failures.txt lists three gate seeds against this issue, each unshrunk:
- 107609900815: "node 1's sync set holds thing 0 as None, the model Some(Keys)".
- 277009481497: "node 0's sync set holds thing 0 as None, the model Some(Read)".
- 527365123461: "node 1 reads thing 0 unlike the reference": node 1 reads None with no roles where the reference reads `Str("v4")` with admin, sync and read roles; its lost access says "not due: no secrets of it held".

Beyond the gate's seeds: re-run seeds 0..60 with public things, redeems, cards and inbox moves.
