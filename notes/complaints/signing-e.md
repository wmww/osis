# signing-e complaints
> Summary: what bit the signing step (e) worker: a local-record prefix collision, tid-order-dependent tests, slow builds at load.

- `records.rs` is not the only home of local-record prefixes: `rotation/lost.rs` defines `l/` itself, so a new `l/` table in records.rs silently shared its key space (every list scan hit lost-access rows). Grep `b"x/` across the crate before picking a prefix, or move every prefix into records.rs.
- `sharing::leave_of_a_links_maker_gives_up_the_link` passed on main only because the link's K sorted after the target by tid: leaving K first stranded the joiner. Any change that shifts rng draws (so tids) flips such tests; finding it took two `tools/bin-at` builds. Fixed (the target's grant goes first), but other set-ordered flows may hide the same.
- At load 30-40 an engine-only build took 5-12 min and the workspace test build about 15; `tools/bin-at` 4-6 min per probe.
