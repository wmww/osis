# join-cost
- `pkill -f <pattern>` matched its own shell's command line and killed the whole Bash call (exit 144): list the pid with `ps` first.
- A `--toggle-collect` on an `#[inline(never)]` wrapper silently collected nothing: two wrappers with the same body folded into one symbol (`last_settle`, `fill_rest`); the empty profile only showed after a 4-minute valgrind run.
- `World::step` does not accept invites, only `run` does: a stepped fill spun forever with the joiner holding nothing and no error. The stepped measure now has an idle bound.
- callgrind on a chat of 80 members did not finish in 20 min (the joins run under it too); native spans by size told the same.
