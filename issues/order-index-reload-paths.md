# held_set_decides_plain: a commit's index entry differs after the store is loaded afresh
> Summary: `order::held_set_decides_plain` fails on main (595fa6faf) at seed 610247967197 (PartsAway): a session-form content commit writing two things keeps both things' paths in the live index, but the store loaded afresh rebuilds it with one.
> Priority: normal
> Tags: tests, engine

- Replay: `OSIS_ORDER_SEED=610247967197 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks it). Found by a gate at offset 610247967197.
- The engine's rebuild check (`engine/mod.rs`, "rebuilt from the commit records"): the commit's `paths` holds `t:list.0`'s thing and `t:map.0`/`t:rec.0`'s thing live, only the first after reload. A reload reading differently from the live node is a restart changing state.
