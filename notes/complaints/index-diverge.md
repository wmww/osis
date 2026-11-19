# index-diverge
> Summary: Workflow notes from fixing a released thing's vouch left in perm's held set.

- The issue's framing (trimmed parts in a random order) was a guess from the repro; the cause was `packages_to`'s own sync on a copy of the net (the panic is in the copy's drop). A backtrace of the panic frame (`RUST_BACKTRACE=1`, look for `packages_to` / `drop_glue`) said so at once.
- The index check names the differing row (`Held(tid)`) but `held_digest` shows only edge commits and the record, not vouches: a `([], false)` entry means "something perm reads on it beyond those". A probe printing `Held`'s maps for the tid found the vouch.
- A first full `-p osis-engine` run caught a `Core::mark` assertion (held set touched, timelines not updated) only on the lost-access forget path: a held-set change inside `unindex` needs its own `update_timelines`. Running the single failing tests first would have missed it.
