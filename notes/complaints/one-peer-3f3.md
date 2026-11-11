# one-peer-3f3
- The wip branch was built on an older one-peer-3f2 head (rebased since): `git rebase --onto one-peer-3f2 <old 3f2 head>` was needed, and the brief's "rebase onto 3f2's current head" did not say which base the wip sat on.
- `Faults::at` resets the write counter: `faults.at(w0 + k, ..)` after earlier writes silently plans the crash far past the flush (and `writes() - w0` underflows). Read the doc line before reusing it.
- Editing sources while a background `cargo test` runs is fine for the run (it compiled first) but its results then describe the older tree: rerun after the edit.
