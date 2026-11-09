# held-set-decides
- The plan's "node tier 1 down by about 40%" came from the pre-step-4 measurement (`order::` 604 CPU-s); on main before this step `order::` was about 160 of about 990 CPU-s and the scripted `*_alike*` tests about 80, so the listed deletions cannot reach 40%. Measure the target's share before writing a done-when number.
- Turning a printed `Step` history (`vec!{steps:?}`) into a literal needs `Aim(..)`/`Old(..)` wrapped in `Box::new` and `Role::` on roles; a `Step` printer that emits Rust would make issue replays cheap.
- Durable covered drops happen in node-sync (`sync/local.rs drop_covered`), never in an engine-only harness: a keep-bound sabotage on that path is invisible to `held_set_decides` (it was to the old order harness too).
- Review: the coverage floors pass at the tenth-size plain runs the branch was checked at, but a random offset hit a floor (Lists had no start reaching its outcome) and `OSIS_FULL=1` failed 5 of 80 seeds. A new property needs one full-size run at a random offset before it lands.
- Review: a background `cargo test` picks up edits made while it waits between two cargo invocations; keep the tree still until the second build starts.
