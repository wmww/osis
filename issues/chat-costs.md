# Chat join, message and removal cost far over the notes/chat.md estimates
> Summary: (Engine waste fixed in sync round 2; design knobs left.) Measured through examples/chat `costs_join_message_removal` (chat of 4, upstream bytes) before the fix: join ≈ 220 KB, message ≈ 2.5 KB, removing a link joiner ≈ 300 KB from the moderator plus ≈ 160 KB from the others. About two thirds is engine waste: re-uploads, whole-commit and duplicate certificate copies, and copies placed then deleted. Without the waste, the design costs about 38 KB per join, 2.1 KB per message and 45–80 KB per removal at 4 members (at 200 members, ≈ 0.55 MB once the double rotation and the home-label copy are gone). The "never settles" case is an endless rotation loop (fixed, notes/node.md).
> Tags: performance, sync, node, tests

Repro: `cargo test --release -p chat -- --ignored costs_join_message_removal --nocapture` (fails its design budgets).

Status: the engine waste (re-uploads, certificate copies) is fixed (sync round 2): the test measured join 41 KB, message 2.5 KB, removal 70 KB from the moderator plus 15 KB from the others before flows round 2 merged; after it, join 63 KB, removal 85 KB plus 68 KB from the others (not attributed yet; the test asserts the design budgets and is ignored with this issue until they hold). Left here: that regression and the design knobs in (b).

## Breakdown (chat of 4: alice, two link joiners, a late joiner; blob bytes, KB)
Each entry adds about 120 B of frame overhead (wrap 49, stamp 64, framing) on top of the blob bytes below. Attribution comes from a temporary per-entry log in `SyncEngine::command` (blob class, commit, aspects, delta sizes), not committed.

| step (sender) | total | (a) re-sends | (a) cert dup / churn | (a) `/secrets` in cert copies | design |
|---|---|---|---|---|---|
| join (late joiner) | 204 | 146.5 | 19.9 | 0 | 37.6: chain certs 23.5 (2 labels × 11.8), membership 7.5, content 2.0, inbox 4.5 |
| join (alice) | 6.1 | 4.1 | 0 | 0 | 2.0: the persona commit again under alice's home label (C sits in her home) |
| message (alice) | 2.08 | 0 | 0 | 0 | 2.08: 3 blobs of one commit, each with the 467 B header |
| removal (alice) | 285 | 171 | 21.1 | 13.8 | 79: two K and two C rotations with copies under K, C and home; `/label`; content; inbox |
| removal (each other member) | 68–87 | 48–67 | 19.3 | 0 | 0.4: heartbeat |
| removal, chat of 8 (alice; others send 977 KB of frames) | 993 | 791 | 43 | 35 | 124 |

Inside the commits: a rotation's `/keys` is 2.6 KB (2 hybrid KEM keys of 1216 B). K's `/secrets` costs 2.7 KB per remaining member (a read and a write sealed box) plus about 2.2 KB fixed (link-key box, history boxes). C's rotation is 4.2 KB, because K is C's only boxed member. A person's keyset is 5.2 KB, a node card 1.7 + 0.5 KB, a heartbeat 0.4 KB.

## (a) Implementation waste, fixes, savings
- Re-uploads: a writer sends every stamped entry again on each pass until the server answers. Fixed (sync round 2). Saves ≈ 150 KB per join, ≈ 170 KB from the remover and ≈ 50–65 KB from each other member per removal. These dominate, and they grow faster than linear (chat of 8: 790 KB).
- Certificate copies (fixed in sync round 2):
  - After a rotation, `place_all` copies the whole commit, `/secrets` included, under C. The chain projection is `/keys` + `/members`: 13.8 KB extra per removal now, ≈ 530 KB per K rotation at 200 members.
  - It duplicates the closure blob under K's own label: 21 KB.
  - Members upload chain projections that the admin's fuller copy makes must-not-hold, and the admin deletes them: ≈ 19 KB per member per removal.
  - Joiners re-place chain commits already under the label: ≈ 20 KB per join.
- Endless rotation by a writer that cannot judge coverage: fixed (notes/node.md, rotation loop).

## (b) Design costs (the spec as written) and the knobs that would change them
- **Projections repeat the header**: one blob per (readable subset, retention class), and the token set differs per thing. A message is 3 blobs: its `/created` (fixed retention), its text + sent time, and the placement on the persona's `/group`. Each repeats the header (467 B: 4 aspects with a 32 B delta hash each, 3 tokens) and the signature. Knobs: the header and signature travel once (projections carry the commit ID and parts; costs a second fetch), ≈ −1.1 KB; or the app drops the placement and finds messages by owner (needs a query), ≈ −0.7 KB.
- **Chain certificates per label per node**: a joiner places its chain (node card, node and person `/keys`, `/created`, the edges up to C) under every label it writes, K's and C's: 11.8 KB each. Knob: a certificate already under the label from any node counts, so a node places only the commits the label lacks (spec/permissions.md §4 now says per node). This is the same rule as the (a) fix but allowed across authors. ≈ −5 KB per extra label for later joiners.
- **One hybrid KEM key per role**: `/keys` carries 1216 B per role, so a person keyset is 3.6 KB of KEM keys and every rotation `/keys` is 2.4 KB. Knob: one KEM key per keyset, with role boxes told apart by AD: −1.2 to −2.4 KB per keyset and per rotation.
- **Sealed boxes per member per role**: a link joiner needs K's read and write, which is 2 sealed boxes of ≈ 1.35 KB. Knobs: one sealed box per member carrying all its roles (as key actors already get) halves removal: ≈ 1.35 KB per member. Symmetric 49 B boxes apply only where the writer holds the member's secrets: an admin's own actors, not other people's persons.
- **Two rotations per removal of a link joiner**: `demote(K, joiner)` and `revoke_link(K)` each rotate K and then C. A membership commit changes one edge and a removal carries its rotation (spec/commits.md §2). Knob: a link revocation that removes the joiner and the link key under one rotation (a two-edge removal commit, or the first removal deferring its rotation to the second within one flow). Halves the removal: 79 → ≈ 45 KB now, ≈ 2.2 → 1.1 MB at 200.
- **Closure of the home label**: the app places C (and the link places K) in alice's home group. Every commit touching them then also goes under her home label: the rotations' `/secrets` again (18.5 KB per removal at 4, 40 KB at 8, ≈ 540 KB per rotation at 200), and persona and `/group` commits. Knob (app or API): reach chats through the `/label` cross-publish only, not as home items.
- **Claim sets**: padded to a power of two, 32 B per slot: 2–4 slots here, 8 KB per step per label at 200. Minor.
- Not measured: downloads (each member fetches K's rotation once per label it syncs, so the C copy without `/secrets` matters most at scale).

## (c) Estimate mismatches in notes/chat.md
- The message estimate (350 B + content) counted one header and no projections. It is 3 blobs, ≈ 2.1 KB + frames.
- The join estimate (four commits, three boxes) left out chain certificates under two labels (23.5 KB), the persona's own keyset (3.6 KB of KEM keys), two inbox blobs (4.5 KB) and the per-thing projections.
- The removal estimate (2 boxes per remaining member) is right for the boxes: 2.7 KB per member per rotation is measured. It left out the second rotation, the cert copy under C, the home-label copy, `/keys` and `/label`.

## Honest design cost (with the (a) fixes, spec unchanged)
- Join ≈ 38 KB (chat of 4, independent of size apart from K's grant).
- Message ≈ 2.1 KB of blobs, 2.5 KB on the wire.
- Removal of a link joiner ≈ 79 KB at 4 members (≈ 45 KB with one rotation). At 200 (all through one link): ≈ 2.2 MB as specified (two rotations, each with K's 540 KB `/secrets` under K and again under alice's home), ≈ 0.55 MB with one rotation and no home copy, which is close to the old estimate. Other members send ≈ 0.4 KB each.
