# held-set-decides
- The plan's "node tier 1 down by about 40%" came from the pre-step-4 measurement (`order::` 604 CPU-s); on main before this step `order::` was about 160 of about 990 CPU-s and the scripted `*_alike*` tests about 80, so the listed deletions cannot reach 40%. Measure the target's share before writing a done-when number.
- Turning a printed `Step` history (`vec!{steps:?}`) into a literal needs `Aim(..)`/`Old(..)` wrapped in `Box::new` and `Role::` on roles; a `Step` printer that emits Rust would make issue replays cheap.
- Durable covered drops happen in node-sync (`sync/local.rs drop_covered`), never in an engine-only harness: a keep-bound sabotage on that path is invisible to `held_set_decides` (it was to the old order harness too).
