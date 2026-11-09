# held_set_decides plain fails three seeds at full size, on main too
> Summary: Three seeds of `order::held_set_decides_plain` at `OSIS_FULL=1` fail alike on main bd95cf774 and on the expiry-5 branch: two arrival-order differences and a persisted-index mismatch. Not yet studied.
> Priority: normal
> Tags: engine, tests

Replay with `OSIS_ORDER_SEED=<s> OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain`.
- 758421392942 (Settled): text reads `v7v1` where the node keeping every body reads `v1`.
- 758421392937 (Keeps): held-model reads a `k0` entry of `t:map.0` the node does not.
- 758421392977 (Keeps): opened from the persisted index, `secrets` holds an empty `ActorEpochs` in memory and nothing on disk.

Plain size (a tenth) may not reach them; not checked.
