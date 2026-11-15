# client-port complaints
- `for w in std::mem::take(&mut *lock(&m)) { w.wake() }` holds the lock for the whole loop (a temporary in a `for` head lives to the loop's end): a waker that polls in place deadlocked on it. Fixed in `ReadOnly::locked`; look for the same shape elsewhere.
- A hung test gave no backtrace: gdb cannot attach (ptrace_scope), so a deadlock is found by reading; `/proc/PID/task/*/wchan` at least tells blocked from spinning.
- `cargo test -p osis --test it port::a port::b` treats the second name as a cargo argument and runs nothing; filters go after `--`.
- `wait_synced(Thing(t))` on a thing accepted from another account's grant (two nodes on the test network, cards imported both ways) never resolved within 20 `run`s, in process too; not looked into (out of this branch's scope).
- (review) A listener on a group the actor may not read heard commit ids of writes to items it reads (in process too): `commit_event` checked only the commit's things. Probe every address form (group, aspects) when checking access, not only a thing.
