# held_set_decides_plain: a node keeping every body shows a purged message after sync
> Summary: `order::held_set_decides_plain` seed 86543989744 (`OSIS_ORDER_START=86543989739`, Purges emphasis) fails on main: after the sync exchange, a node shows `m8` on `t:msg.0` where the node keeping every body shows none. Fails the same before aged-covers (7c7ef5cbe~1) and at main d80141197; not the deposit-storm change. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, node

- Replay: `OSIS_ORDER_SEED=86543989744 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks it). The history purges message authors and named messages repeatedly (`PurgeAuthor`, `PurgeNamed`), with demotions, a leave and a removal.
- Want `Ok(None)`, got `Ok(Some(Str("m8")))`: either a purge reached one node and not the other, or the reference node's purge view is wrong. Undiagnosed.
