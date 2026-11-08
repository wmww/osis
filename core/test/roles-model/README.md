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
| `epochs-exh` | 0 (families A and B) | below |
| `digest` | 1,000,000 | notes/testing.md, Models |

## Epochs (`src/epochs.rs`)
One account P (node 0 the remover, X = 1, Y = 2, maybe a sibling), witness writers of other accounts, an optional admin demoting P on thing 0, one outsider. Things sit in one or two labels (a thing may sit in both); every node opens some labels. Generated: content and snapshots by any node, X's removal and in some worlds Y's after it, X re-added, a sibling's concurrent rotation, removed nodes' forks, counter-merges, backdated writes and own listings, witness snapshots that fall, part bounds of 1 or 2 IDs, covered commits omitted or listed; honest listings and addenda after every change. Checked at every observer and every prefix of its receipts:
- Safety: no write by a node while removed counts at an observer siding with node 0's line and holding a counting rotation made at or after that removal; counted apart: a removed node's fork counting (the window until node 0's merge arrives), an unaware sibling's rotation or listing naming it (stated limit), a re-added node's later word reviving it, a witness's valid snapshot carrying it (stated limit).
- Liveness, at observers holding everything an honest party holds under their labels: every legitimate content commit some party whose word stands received in time (oracle from the history alone: a final member's receipt or its own authorship, a witness's before the closer's `ts`, a rotator's list, a chain of honest listings) is visible; nothing is visible beyond the upper bound (receipts before any closer's `ts`).
- Monotone: dropping an honest list, listing or addendum never makes more valid.
- Omit-covered loses nothing against listing every commit.

Hand tests (`cargo test -p roles-model --lib epochs`) state the properties of the build plan's steps 4 and 5 on small worlds.

### Results
At the current commit: **hole found** (AMBIGUITIES.md 1): a sibling's rotation made before X's removal reached it boxes X an epoch the removal does not close; X then signs there, forks from there to void its removal, and node 0's merge lists what X wrote there. `removed_node_holding_a_sibling_epoch` (ignored) is the minimal reproducer; `random_worlds_hold` fails on it.

| Run | Worlds | Wall (16 threads, load 20-35) | Hard failures | Of them in worlds with a sibling's rotation |
|---|---|---|---|---|
| `-- 1000000 epochs` | 1,000,000 | 93 s | 15,114 (15,072 safety at a sibling's epoch, 42 liveness) | all (103,299 worlds have one) |
| `-- 0 epochs-exh` A (one label) | 939,470 | 47 s for A and B | 0 | 375,788 have one (X's own before its removal) |
| `-- 0 epochs-exh` B (new dimensions) | 1,283,040 | (with A) | 0 | none |

Dimension counts, random run: several labels 333,059 worlds; a thing in two labels 241,692; the rotator missing a label holding P's content 62,281; successive removals 326,798; re-adds 333,115; a part past the bound 42,645 (plain content past it saved through the rotator's listings 47,980 times); a rotation refused by the bound 17,511 (10,581 left a removed node's fork standing: final readings not checked). Final readings: a listing at a closed epoch counting 603,216 times; content saved under a label the rotator did not open 26,814; a re-added node's writes from while removed revived 79,071. Counted: fork window 272,123 observer-prefixes; unaware sibling 1,213; listed write pending its part 959,720; disputes in 148,043 worlds.

Family A: 2 P nodes, 1 witness, 1 outsider, one label and thing, X removed at 3; one or two content commits (author, time 1..4, backdated, receipts immediate, late or never), X's rotation before or after its removal or none, X's counter-merge, a snapshot none / by node 0 / by the witness (falling or not), covered commits omitted or listed. Family B: 3 P nodes, labels L0 and L1, things in L0, in both, in L1; node 0 opens L0 or both, Y one or both, X both; a witness on the shared thing or the L1 thing; the outsider one label or both; X removed then Y, X removed and re-added, or both; bound none or 1; one content commit (author, thing, time 2/4/7, plain or special, receipts of node 0, the other P node and the witness immediate, late or never) alone or with one of four companions. Neither family has a sibling's concurrent rotation boxing a removed node after its removal (A's only sibling rotation is X's own, before it), so neither reaches the hole.
