# A commit's late part without its author's chain: state depends on arrival order
> Summary: a commit spanning two things, its author's chain held for one only: part A first applies the commit and A's write joins, part B first holds the commit pending whole and A's write does not; a violation of spec/requirements.md Decentralization for as long as the chain stays away, which a hostile author can make forever.
> Tags: tests, permissions, engine, spec

Repro: `cargo test -p osis-node --test it -- --ignored repro_chainless_part_order` (fails).

`apply::examine` checks the chain per aspect, only for aspects whose delta is held or synced. 1 writes one commit on G (held edge) and H (no held edge from 1 to H):
- G part first: H neither held nor synced: the commit applies. The H part then waits (`MissingChain`), the commit both applied and listed pending.
- H part first: the commit is pending. The G part joins the pending blob and waits with it: G's write is not in the state.

Same held set, different G state and the same `waiting`. It needs a commit with a thing the author has no path to (a writer refuses one: hostile only) and a node that receives both parts. The order harness splits multi-aspect commits but its authors always have every chain.

spec/commits.md §4 lists the chain among reasons a whole commit is pending, without saying what a later part does. Likely fix: judge the wait per part (`each delta is judged on its own`): a part whose thing the author's chain does not reach waits alone and the rest applies, in either order. Then pin both orders in `judgment/labels.vec`.
