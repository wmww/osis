# A death dated early or missing at one arrival order, seed 733028
> Summary: `order::arrival_order_alike_large_spec_permissions_5_2` fails at seed 733028 on main (2964db75): a delete under keep at most 0 goes on arrival, beaten by a held undelete, then the creation arrives: its body has no death here and stays for good, where other orders drop it. Needs a decision: state a limit or build a residue.
> Tags: engine, retention, tests

Replay: `OSIS_ORDER_SEED=733028 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored` (about 90 s). Held 15 of 23 commits, order #2: `death dated early or missing` on a `t:docs.0` delta, `here None`, earliest superseders present. Same text on main and on keep-in-removal, so not that branch's. Its history has `Undo`, `Breaking` and `Require` steps. 1 of 60 from 733000.

Also seed 8210052 (same oracle, same text, on main 765e91c6 and on simplify-retention): `t:reg.0`, `here Some`, earliest superseders `None`, history with `Require`, `Breaking`, `Compact`, `Demote` and `Forged` steps, no purge. 1 of 60 from 8210000. Replay as above with `OSIS_ORDER_SEED=8210052` (about 80 s).

Not the cause of seed 27243 (a separate fix). Found by probe, on main and with that fix:

Shrunk: `h = vec![Aim(Demote { by: 0, t: 7, holder: 2, at: 4, to_read: true }), Aim(Leave { by: 1, t: 7 }), Aim(Require { by: 0, t: 1, op: 18, rule: 3 }), Aim(Breaking { by: 0, t: 1, op: 6, v: 1, fits: false }), Aim(Breaking { by: 0, t: 1, op: 6, v: 1, fits: false }), Send { from: 0, to: 2, back: 2 }, Aim(Nested { by: 0, other: 2, t: 3, k: 2, text: true, compact: false, also: false }), Aim(Undo { by: 2, back: 1 }), Aim(Typed { by: 1, t: 0, op: 1, k: 0, v: 4 }), Aim(Edge { by: 0, t: 2, holder: 1, role: Some(Write) }), Aim(Typed { by: 2, t: 4, op: 3, k: 2, v: 7 }), Aim(Undo { by: 2, back: 2 }), Aim(Typed { by: 0, t: 4, op: 7, k: 1, v: 3 }), Aim(Typed { by: 0, t: 3, op: 10, k: 1, v: 6 })]`, held `[0..=8, 10, 15, 16, 17, 19, 20]`, order `[10, 3, 7, 17, 16, 20, 4, 2, 0, 19, 8, 1, 6, 5, 15]`.

Three `t:docs.0` bodies under keep at most 0: #15 creates the text, #16 deletes it, #20 undeletes it. Delivered #16, #20, #15: the node drops #16 (no live write, spec/commits.md §5), keeps no residue of it, and when #15 arrives nothing it holds supersedes the creation, so #15 has no death. That part follows the spec: a superseder that left dates nothing. As made, #15 dies at #16 and, its write live, drops at its grace bound.

Two oracle checks fail on it. `dating`: no death where the oracle, which keeps every body, has one. A local `(None, Some(y), false)` excuse when `y.0` is the `ts` of a body dropped here passed that check and was taken out again, because the second one remains: the index a day later differs (`dropped: {0}` vs `{}` on #15's commit), for good, while #15's write stays live. The value is in the state either way, so nothing readable differs.

Options: (a) state the limit in §5 (a body whose only superseder left before it arrived has no death and stays while its writes live) and excuse exactly that in `dating` and the index compare; (b) keep a residue for such a delete, more machinery. By the owner's ruling on rare shapes, (a) looks right. The unshrunk run (`OSIS_ORDER_SHRINK=0`) fails earlier as `states on t:docs.0`, at a partial set then the rest; not yet read, it may be a further cause.

