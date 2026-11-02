# A body's class moves after a drop was judged
> Summary: a body's class reads what is held (`retention::reader`), so a keep-at-most drop judged while the class was smaller differs from one judged after: same held set, different bodies kept.
> Tags: engine, retention

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_body_class_move`.

Commit on G and H, same owner, both keep at most 0; H's record away, H unsynced, so H's part waits alone (spec/commits.md §4). A later commit kills G's write. With the record held first the class is {G, H}: H's write is live, so G's part stays until the grace. With it last the class is {G}: no live write, G's part drops in the killing transaction with its death row, and H later reads no death. Reads agree; the bodies kept and the deaths differ. Death rows per part (`body_class`) fixed the lost-row half (order seed 83156), not this. `own_keys` growing moves classes the other way: a split, so one order's class drop takes a part the other's keeps.

Options: judge no drop of a commit's body while a part of the commit waits (a never-arriving record then only delays a drop, which keep at most allows only within its grace: check spec/commits.md §5), or define the class from the header alone. Needs a look at how far spec/commits.md §5 "a projection" can read the header alone.
