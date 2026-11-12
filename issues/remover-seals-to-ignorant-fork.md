# A remover lacking M's keys seals to an ignorant fork of M ordered after its own removal
> Summary: An admin of holder actor M through a keyless grant (no M secrets) removes P from M, then seals A to a keyset of M made by another admin of M without knowing that removal but ordered after it; P reads A's new content, even after the same admin removes P from A directly, until M's knowing keyset reaches it. The stated order-alone limit (spec/crypto.md §4; spec/requirements.md Permissions). Tess: keep the limit, or close it where the node holds M's timeline (names digest check below).
> Priority: low
> Tags: security, rotation

Plain version for Tess: Alice is an admin of team T only through another group, so she holds none of T's keys. She removes Bob from T. Before anyone tells them, two of T's own admins change T's keys and still include Bob. Alice then shares group G's new content with T, picking the newest T keys she sees, which are those Bob-including keys: she cannot tell whether they were made knowing her removal. Even after she also removes Bob from G directly, Bob keeps reading G's new content through T until one of T's admins changes T's keys knowing the removal. The requirements allow this ("once M's keys were changed knowing the removal"), but a user who removed Bob from both groups would not expect it.

Shape (`rotation_holds_large_spec_crypto_4` seed 618244500061; probe dump of grants and actor-to-actor boxes): A2's holders A0 and A1 are keyless (no box from A2 to any actor in any state); A1 holds Read on A0 and A2 Read on A1, both keyed. Peer 0 (A2 admin via A0) removes peer 3 from A2, no rotation. Peers 1 and 2 rotate A2 unaware (n2 forks boxing peer 3). Peer 0 seals A1 Read n2 to A2's fork n2.56 (ordered after the removal), and its removal of peer 3 from A0 makes A0 Read n5 boxed to A1 at n2. Peer 3 opens n5 by: its direct box at A2 n2.56 -> A1 n2 -> A0 n5.

Why the node cannot tell: rotation commits carry no frontier; a rotation's names are inside the history box (under M's secret); `keys.0` carries only their digest.

Option (unstudied): a node holding M's role timeline computes the names digest of the lowerings on M it holds ordered before the keyset, with and without its own departure; a match with it proves knowing, a match without it proves ignorance (leave M out); neither, judged by order as now. Needs the exact names set to be reproducible from the timeline (every lowering held, departs mark), and costs a digest per candidate keyset. Rejected already: counting every keyset ordered after a departure as uncovered (notes/crypto.md: bars a reader of M from ever sealing M's write role once a writer left M).

## Decision
Tess: accepted as a limit for now. Not stated in spec/requirements.md; fix it if a way without significant tradeoffs appears.
