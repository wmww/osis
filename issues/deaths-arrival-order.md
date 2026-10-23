# Body deaths depend on arrival order
> Summary: A write's first death is the `ts` of whichever superseding commit arrived first, not the earliest one; only keep-at-most aspects are corrected (`note_earlier_deaths`). Deaths feed keep-at-least (`MEMBERSHIP_KEEP` included) and keep-at-most bounds.
> Tags: retention, node, security

spec/crdt.md §4.8: a write dies at the earliest `ts` among the applied commits whose writes supersede it, each judged against the write alone. A join reports deaths against the state only: with writes X < Y < Z on one register, Z arriving before Y kills X at Z's `ts`; Y then loses to Z and never meets X, so X's first death stays at Z's `ts` (it should be Y's). Same for `/members` entries (several edge writes on one member) and anything else a later write supersedes.

Repro: `cargo test --workspace --test it order::deaths_alike -- --ignored` (osis-node `order.rs`, seed 16: G's first `/t/reg` value superseded by A's write and B's later-stamped one, delivered in either order). The arrival-order harness compares deaths only for keep-at-most bodies; `OSIS_ORDER_DEATHS=1` compares every body (6 of 40 small seeds differ, shrunk seeds 1, 9, 10, 16, 18, 24, 39).

Effect: a body's keep-at-least bound (first death + D) differs between nodes holding the same commits, so one node may drop (or delete at a server) a body another still must hold; for membership bodies under `MEMBERSHIP_KEEP` a node may drop certificate material early.

Fix direction: what `note_earlier_deaths` does for keep-at-most (join a new delta alone with each held body of the aspect and lower recorded first deaths) generalised to every body with a keep bound, at O(held bodies of the aspect) per delta; or record deaths per (write, superseder) from the state's write stamps without re-joining. Last deaths (`last`) need the same review.
