# Window deaths differ from a whole replay (debug assertion)
> Summary: The order oracle at seed 7233 panics in `retention/deaths.rs` (debug check after judging window deaths): a held bounded body on `/t/gonemap` has no death where a whole replay dates one. Independent of osis-perm (same on main's perm).
> Tags: retention, node, tests

Repro: `OSIS_ORDER_SEED=7233 cargo test --workspace --test it order::arrival_order_alike_large -- --ignored` (panics at deaths.rs:744, "window deaths of … on … \"/t/gonemap\": None, a whole replay Some((t, t))"). The panic aborts the run before `shrink`, so no shrunk history yet: catch it per order (or turn the check into an error) to shrink. Maybe the same family as deaths-dropped-superseder.md (a residue dropped before a body that it dates arrives).
