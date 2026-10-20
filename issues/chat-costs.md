# Chat join, message and removal costs: the wire-format knobs left
> Summary: Engine waste and the implementation knobs are done: in a chat of 4 a join sends 41 KB, a message 2.5 KB, removing a link joiner 26 KB plus about 3 KB per remaining member (37 KB at 8, ≈ 0.6 MB at 200), and the other members only heartbeats. What remains is the wire format: every message pays its header three times (2.5 KB for a few bytes of text), every keyset carries one 1.2 KB post-quantum key per role, and a removal seals two boxes per remaining member. Changing those would roughly halve messages and removals.
> Tags: performance, sync, node, crypto, tests

Repro: `cargo test --release -p chat -- --ignored costs_join_message_removal --nocapture` (tier 2, asserts the budgets below with margin; `OSIS_CHAT_N` sets the size). `OSIS_TRACE_UPLOADS=1` prints one line per entry sent (blob class, commit, aspects; `SyncEngine::trace`).

## Measured (upstream frame bytes)
| step (sender) | chat of 4, before | chat of 4, now | chat of 8, now |
|---|---|---|---|
| join (late joiner) | 79 KB | 41 KB | 41 KB |
| message (alice) | 2.5 KB | 2.5 KB | 2.5 KB |
| removal of a link joiner (alice) | 85 KB | 26 KB | 37 KB |
| removal (all other members together) | 68 KB | 1.1 KB | 3.3 KB |

Chat of 16: removal 61 KB, others 7.8 KB. "Before" is the start of this round (after sync round 2 and flows round 2). What changed:
- Chain certificates per label, not per node (spec/permissions.md §4): a copy or closure blob of the same commit placed by any node counts; closure parts are never copied (a copy duplicating them was deleted as a strict subset); another node's fresh demotion or new `/keys` is left to its author for 30 s (`SETTLE_MS`), so members that learn of a rotation under another label first do not all copy it. Join 79 → 41 KB, others 68 → 1.1 KB, removal 85 → 70 KB. The regression after flows round 2 was this: joiners copied every other node's chain (the sharer's card, person and recovery key) under both labels, and every member re-placed K's and C's new `/keys` after each rotation.
- One rotation per link-joiner removal: `revoke_joiner` removes the joiner and L in one commit (spec/commits.md §2). 70 → 34 KB.
- The chat actor is no longer placed in the creator's home group (app choice, notes/api.md). 34 → 26 KB.

## Breakdown now (chat of 4, blob bytes; about 120 B of frame per entry on top)
- **Join 41 KB**: the joiner's chain certificates under K's and C's labels, 11.5 KB each (its node card 3.1 KB, its person's creation commit 8.4 KB: the person keyset 5.2 KB and the recovery key's 2.2 KB, mostly hybrid KEM keys of 1216 B per role); the grant on K 1.2 KB and its copy under C 0.5 KB; the persona's own secrets 5.4 KB, its grant on C 0.9 KB, its content commit 2.0 KB (3 projections); two deposits 4.5 KB (the grant copy under the joiner's home, the inbox blob to C).
- **Message 2.1 KB of blobs**: one commit, 3 projections (`/created`, text + sent time, the placement on the persona's `/group`), each repeating the 467 B header and the signature.
- **Removal 26 KB**: K's rotation with both removals 9.8 KB (2.7 KB per remaining member: a read and a write sealed box; `/keys` 2.6 KB; link and history boxes), its certificate copy under C 3.4 KB (spec/permissions.md §3), C's rotation 4.2 KB, the `/label` steps of K and C under their labels and cross-published under the home label 3.6 KB, inbox blob to the removed joiner 1.9 KB, registrations 0.9 KB, the persona leaving C's group 0.4 KB. Each further member adds ≈ 3 KB (boxes plus claim-set slots).
- **Others**: a heartbeat each (0.4 KB).

## Remaining knobs (wire format; not done, each needs a spec change)
- **Header once per commit**: projections carry the commit ID and their parts, the header and signature travel once (costs a second fetch). A message 2.5 → ≈ 1.4 KB. Or the app drops the placement and finds messages by owner (needs a query API): ≈ −0.7 KB.
- **One KEM key per keyset** (role boxes told apart by AD): −1.2 to −2.4 KB per keyset and per rotation. A join ≈ −7 KB (person, persona, recovery key), a removal ≈ −4 KB (K's and C's `/keys`, the copy under C).
- **One sealed box per member for all its roles** (as key actors already get): a removal's per-member cost 2.7 → 1.35 KB, so ≈ 0.6 → 0.33 MB at 200 members.
- **Claim sets**: padded to a power of two, 32 B per slot; 8 KB per step per label at 200. Minor.
- Not measured: downloads (each member fetches K's rotation once per label it syncs).
