# held_set_decides_plain: a role commit held-model applies, the node does not
> Summary: `order::held_set_decides_plain` fails on main 829d40c59 at `OSIS_ORDER_SEED=895280621181 OSIS_ORDER_LEN=60` (emphasis PartsAway): with every commit held, as made (order #0), held-model applies role commit #49 (author 0's own edge write on thing 17: admin, invite admin) and the node does not.
> Priority: normal
> Tags: tests, node

## Repro
`OSIS_ORDER_SEED=895280621181 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (2 s of checking). Failure:

    held [0..71] of 72 commits (base 12), order #0 [0, 1, ..., 71]: now: held-model differs: role commit CommitId(0f2cf12fae4e4284..) (#49) on Tid(ySKWbeO0C1RveHZP-hz1) applies: model true, node false; node's roster {Tid(amd14zj4z401zHh-Q71l): Edge { role: Admin, ... }}

Model thing 17 is minted with first admin 16 (`Admin(16)`, 16 itself `Admin(0)`). #49 (author 0) writes 0's own edge `admin`, invite `admin`; later role commits on 17: #55 and #58/#63 by author 4 (0 to write, read), #62 by 0 removing its own edge. Not a clock or arrival-order case (the as-made order, judged now).

## Next step
Decide whether 0 holds edge-admin authority on 17 at #49's time through its first-admin chain (spec/permissions.md §5.1), so whether the node or held-model is wrong; then a small reproducer.
