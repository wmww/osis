# deaths_never_early forces drops of bodies still in history
> Summary: osis-node retention.rs `deaths_never_early_random_large` seed 987589575840 fails ("replaced here Some, with every body None"): the harness drops a later snapshot that is still in history (`Engine::drop_body` skips the keep bound), so an earlier snapshot whose dead writes it carried gets a date again. No valid covered drop does this (notes/engine-retention.md Replaced, the invariant); the harness or its (Some, None) check needs a decision, and loosening it was not done without one.
> Priority: normal
> Tags: tests, retention

- Replay: `OSIS_STRAYS_START=987589575840 OSIS_STRAYS_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact retention::deaths_never_early_random_large`.
- What happens: node 4 force-drops snapshot S2 (`f96d..`) while node 5, holding every body, still dates it inside its one-day keep window. The earlier snapshot S1 (`f9e6..`) had every dead write carried by S2, so node 5 says not replaced (None); with S2 gone node 4 dates S1 at those writes' death (Some). Node 4 keeps S1 longer, the safe direction, but the check accepts only (None, None) or (Some x >= Some y).
- Options: drop only past `drop_from` (as node-sync and `setting.rs` `covered_drops_move_nothing_*` do), or accept (Some, None) as "never earlier" (None means no keep at all). Either changes what the test checks; pick one.
