# roles-model
> Summary: Rust reference models of the role rules (spec/permissions.md §5) and of account signing epochs (issues/account-signing.md): modules, searches with their sizes, and the latest results.

Independent of any osis crate: an oracle, never patched to match the implementation (osis-perm dev-depends on it for its differentials). Module map and API: `src/lib.rs`; findings behind the role timeline: notes/permissions.md; disputes: notes/disputes.md. Choices the spec or plan left open: AMBIGUITIES.md.

## Searches
`cargo run --bin roles-model -- <samples> <mode>`; random searches split their samples over every core, exhaustive ones their families.

| Mode | Size | Checks |
|---|---|---|
| `joint`, `edges`, `disputes` | 2,000,000 | notes/permissions.md, notes/disputes.md |
| `addenda` | 1,000,000 (4 min) | notes/permissions.md, Addenda model |
| `addenda-exh` | 0 (2.83M worlds, 11 min) | as above |
| `epochs` | 1,000,000 | below |
| `epochs-exh` | 0 (families A, B and C; 2.38M worlds, about 1 min) | below |
| `digest` | 1,000,000 | notes/testing.md, Models |

## Epochs (`src/epochs.rs`)
One account P (node 0 the remover, X = 1, Y = 2, maybe a sibling), witness writers of other accounts, an optional admin demoting P on thing 0, one outsider. Things sit in one or two labels (a thing may sit in both); every node opens some labels. Generated: content and snapshots by any node, X's removal and in some worlds Y's after it, X re-added, a sibling's concurrent rotation (made before the removal reaches it, boxing X), removed nodes' forks, counter-merges, backdated writes and own listings, witness snapshots that fall, part bounds of 1 or 2 IDs, covered commits omitted or listed; honest listings and addenda after every change. The rules under test: a counting rotation closes every epoch that does not descend from it (siblings' concurrent epochs included); a merge is signed at each fork it names, and a rotation signed at e rejects nothing on a line through e; one cutoff for every lister (others' commits received before the earliest rotation closing their epoch). Checked at every observer and every prefix of its receipts:
- Safety: no write by a node while removed counts at an observer siding with node 0's line and holding that removal with its chain; counted apart: a removed node's fork counting and making it valid (the window until node 0's merge arrives; the write reads invalid without the removed nodes' rotations), an unaware sibling's rotation or listing naming it (stated limit), a re-added node's later word reviving it, a witness's valid snapshot carrying it (stated limit). A write valid because of something signed at a sibling's concurrent epoch is a hard failure of its own.
- Removal stands: at an observer holding a removal with its chain where every removed node's rotation it holds is signed at an epoch node 0's line is signed at (the removal's own, or a sibling's fork node 0's merge named), the removal counts on the observer's default side. This is the only check of the merge's fork signatures and of "rejects nothing on a line through e": without them the contest ends in a dispute, which the safety check (owner-sided observers only) does not see.
- Liveness, at observers holding everything an honest party holds under their labels: every legitimate content commit some party whose word stands received in time (oracle from the history alone: a final member's receipt or its own authorship, a witness's before the earliest rotation the commit's epoch does not descend from, a rotator's list, a chain of honest listings) is visible; nothing is visible beyond the upper bound (receipts before any closer's `ts`).
- Monotone: dropping an honest list, listing or addendum never makes more valid.
- Omit-covered loses nothing against listing every commit.

Hand tests (`cargo test -p roles-model --lib epochs`) state the properties of the build plan's steps 4 and 5 on small worlds; `removed_node_holding_a_sibling_epoch` is the minimal sibling-epoch world.

### Results
| Run | Worlds | Hard failures |
|---|---|---|
| `-- 1000000 epochs` | 1,000,000 (103,020 with a sibling's rotation) | 0 |
| `-- 0 epochs-exh` A (one label) | 939,470 | 0 |
| `-- 0 epochs-exh` B (labels, successive removals, re-add, bound) | 1,283,040 | 0 |
| `-- 0 epochs-exh` C (a sibling rotating after a removal it has not received) | 160,380 | 0 |

Random run, dimension counts: several labels 333,547 worlds; a thing in two labels 242,426; the rotator missing a label holding P's content 62,410; successive removals 327,754; re-adds 332,982; a part past the bound 41,660; a rotation refused by the bound 15,155 (8,692 left a fork unmerged: final readings not checked). Final readings: a listing at a closed epoch counting 453,944 times; content saved under a label the rotator did not open 26,534; a re-added node's writes from while removed revived 78,886; plain content past the bound saved 46,277. Counted: fork window 167,274 observer-prefixes; unaware sibling 6,538; listed write pending its part 983,518; disputes in 143,731 worlds (249,084 observer-prefixes sided with a thief by default, not checked by the safety check).

Family A: 2 P nodes, 1 witness, 1 outsider, one label and thing, X removed at 3; one or two content commits (author, time 1..4, backdated, receipts immediate, late or never), X's rotation before or after its removal or none, X's counter-merge, a snapshot none / by node 0 / by the witness (falling or not), covered commits omitted or listed. Family B: 3 P nodes, labels L0 and L1, things in L0, in both, in L1; node 0 opens L0 or both, Y one or both, X both; a witness on the shared thing or the L1 thing; the outsider one label or both; X removed then Y, X removed and re-added, or both; bound none or 1; one content commit (author, thing, time 2/4/7, plain or special, receipts of node 0, the other P node and the witness immediate, late or never) alone or with one of four companions. Family C: 3 P nodes (S = 2), a witness and an outsider, one label and thing; X removed at 3, reaching S at 7; S rotates at 3, 4 or 5 (boxing X), reaching node 0 after 1 or 3 ticks; X does nothing, forks at 6 from the newest epoch it holds, or also counter-merges at 9, and lists its own writes or not; one content commit (node 0, S, or X at its newest epoch or epoch 0, time 2/5/7, each other node's receipt immediate, late or never) alone or with one of four companions; no observer sides with X in it.
