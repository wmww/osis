# Held-writes dating and the state disagree on an embedding copy without its register
> Summary: On branch death-dates, `bounds::index_date`'s debug check (`whole_date`, the state's deaths) fails on forged histories (engine `retention::tests_forged::forged_copies_fail_no_node_large`, OSIS_FORGED_START=828121608436/448/460): a snapshot holding a text's embedded chars (derived dots of register write B:108, stamp 393216) without the register write supersedes, by the held writes (spec/crdt.md §4.8: an embedding copy supersedes as its register write), a char created below it that the state keeps winning.
> Priority: critical
> Tags: engine, crdt, security

## What
Three held valid snapshots of one text aspect. One holds char B:10 (created 65536); another holds chars of `Derived(B:108)` created at 393216, no register write. `HeldWrites` names those creations as register write B:108 at the root (`Fragment::held_writes`, `winners.rs` on embeddings), which prunes every lower stamp: B:10 dead at 393216. The state joined from the same bodies keeps B:10 a winner (`deaths` empty), so `whole_date` gives `None` and the assertion fires.

## Which is right
spec/crdt.md §4.8 (When, "a register write also by a copy of its embedding, which supersedes as the register write does") says the held writes: B:10 was replaced at 393216. main dates from the state (`None`: read as live, droppable under a cover), the early direction. So the branch's release date is the spec's and the later one; its debug oracle is what is wrong, and so is the state keeping a write the spec calls superseded (a read showing it). Decide which definition holds (the join pruning under an embedding with no register copy, or §4.8 changed), then make the state and the held writes agree; the check stays an equality.

## Repro
`OSIS_FORGED_START=828121608436 OSIS_FORGED_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact retention::tests_forged::forged_copies_fail_no_node_large` on the branch; passes on main (no such check). Every offset tried fails on two or three seeds (also 41234567008/029, 73456789009/021); the other retention properties pass at those offsets. The reproducer to write: two snapshots as above on one text aspect, seed 0.
