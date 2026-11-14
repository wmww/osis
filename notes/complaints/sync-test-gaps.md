# sync-test-gaps complaints
> Summary: footguns met writing the Phase 4 API-gap tests.

- `common::deliver` carries plaintext packages: a removed node "reads" a post-removal write it has no key for if both arrive in one batch before the lost-access trigger runs. Not a leak, but it looks like one; the retain tests deliver the removal first.
- With sync gone nothing runs the lost-access trigger at the osis level: a test of a removal must call `drop_lost_due` (and, for an `until`, `forget_lost(Only)`) by hand.
- A diagnostic raised inside a read call's lock (an expiry run by `members()`) reaches `on_diagnostic` only after `settle()`; the first full run caught the race.
- `keep_alive` rewrote with `set`, which writes nothing for an unchanged value, so a kept-alive value expired after its first period; fixed to `overwrite` (runtime::keep_alive_rewrites_until_dropped fails without it).
