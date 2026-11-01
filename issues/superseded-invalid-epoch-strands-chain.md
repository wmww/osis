# A rotation superseding an invalid epoch never establishes, and leaves its departure uncovered
> Summary: An epoch is established by chain only once every epoch its rotation supersedes is; a valid rotation that superseded a fork whose commit later turns invalid never establishes anywhere (but at its author, `Own`), nor does any rotation after it, while their box removals apply: the older epoch they superseded stays current with its boxes gone, so it covers every departure and a demoted holder keeps its secret.
> Tags: security, permissions, keys, engine

`rotation::tests::forks_with_departures_settle_large` (osis-engine lib, tier 2), seed 51, G's write role (epochs as n/first nonce byte):
- peer 3, an admin, rotates write (2/126); peer 4, not having it, removes peer 3, rotating write (2/31, boxing writer peer 2): 2/126 is outside the removal's frontier, so invalid at every node once the removal arrives;
- peer 0, having 2/126 but neither 2/31 nor the removal, demotes peer 2 from write to read: its rotation 3/193 supersedes 2/126;
- once synced, peer 0's next rotation (4/133) removes the boxes at 2/31 and 3/193 and supersedes both.

After every re-seal and rotation settles: 2/126 is never established, so neither is 3/193 (but at peer 0: `Own`, issues/own-rotation-invalidated.md), so neither is 4/133 at any other node. Peers 1 and 4 count 2/31 current and newest; 4/133's valid delta removed its boxes, so by the box rule it covers every departure, and peer 2 holds it: peer 4, an admin, signs under an epoch the demoted writer holds, and does not rotate (with read, it would wrap content a removed holder reads). Peer 0 counts 4/133 newest: the nodes also disagree on newest.

spec/crypto.md §4 does say this ("established ... when the node has applied its rotation commit ... and every epoch that rotation supersedes is established"); the chain condition is there so that holding an epoch means holding every departure its chain carried (TLC R9, Residue 1), which an invalid commit carries none of. A likely fix: the chain condition skips a superseded epoch whose rotation commit the node holds and judges invalid (a function of the held set). Then `Own` could be dropped for an invalid own rotation too. Before the reseal-forks branch the same (supersession then also came from `keys.0`).

Seed 243 is the same without the leak: peer 0's rotation of every role, made knowing a read fork of an admin demoted concurrently (so invalid), is established only at peer 0 (`Own`) and at that admin (whose own fork is `Own` there), so those two count it newest and the rest the older fork. In 300 seeds (0..300) these two are the only failures of the test.

Repro: `OSIS_DEPART_START=51 OSIS_DEPART_SEEDS=1 cargo test -p osis-engine --lib forks_with_departures_settle_large -- --ignored` (and 243).
