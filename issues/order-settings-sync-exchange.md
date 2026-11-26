# held_set_decides_plain: after a sync exchange a node reads a t:reg.0 value as none
> Summary: `order::held_set_decides_plain` fails on main at seed 878473417130 (Settings emphasis): after the sync exchange a node shows `t:reg.0` of one thing as `None` where the node keeping every body reads `Some(Str("beside"))`.
> Priority: normal
> Tags: tests, engine, retention

- Replay: `OSIS_ORDER_SEED=878473417130 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (fails on 3f054424b; `OSIS_ORDER_SHRINK=1` shrinks it). Found by a gate.
- `now, after the sync exchange: shows other than the node keeping every body: Tid(..) t:reg.0: want Ok(Some(Str("beside"))) got Ok(None)`. The history mixes retention settings (`Setting`), purge sets, a demotion and forged commits. Unexamined.
