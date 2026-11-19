# held_set_decides_plain: a value lost after the sync exchange
> Summary: osis-engine `order::held_set_decides_plain` fails on main: a RecordOnly or Purges history shows `None` where the node keeping every body shows a value, after the sync exchange.
> Priority: normal
> Tags: tests, engine

Fails on main at 26f8e7280 with `OSIS_ORDER_SEED=874943289203 OSIS_ORDER_LEN=60` (`cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain`; `OSIS_ORDER_SHRINK=1` shrinks it): emphasis RecordOnly, a held set then the rest, `now, after the sync exchange: shows other than the node keeping every body: .. t:reg.0: want Ok(Some(Str("o"))) got Ok(None)` (core/engine/tests/it/order.rs:3338). Found by the gate of gimbal-terms-code (a pure rename), then replayed on main's own binary.

Also fails on main at 9f48cc50c with `OSIS_ORDER_SEED=430540858112 OSIS_ORDER_LEN=60`, emphasis Purges: `t:text.0: want Ok(Some(Str("v6"))) got Ok(None)`, the same check (found by the gate of windlass-s1-idle, replayed on main's own binary). Possibly the same cause; split the issue if a fix tells them apart.
