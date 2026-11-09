# listener-6
- No public way to stop a save in flight at a known point: a "keystroke during a save" test needed a `Knobs::text_save` hook (holding the node lock via `Internals::engine` gives no event for when the other thread reached it).
- `pkill -f <pattern>` matched my own Bash command line and killed it; the edit in the same command silently never ran.
- A single-crate `cargo test -p osis` build sometimes took 3+ min while other agents' heavy runs held the box.
