# code-refs-2
> Summary: Workflow notes from making tools/code_refs.py read Rust doc comments and check `Type::item` members.

- `grep -o` (ugrep) with a `.\{0,140\}` context pattern in a shell loop ran past the 2-minute tool timeout on a handful of lines; Python slicing did the same instantly.
- About 60 stale citations had piled up unseen because code_refs counted a word anywhere, its own citing comment included; most were an item cited on the wrong type (`Core::snapshots` for `Indexes::snapshots`, `Serve::` for `Streams::`, `Ui::copy` for `Started::copy`).
- Policy timing swings 2-5x with box load (load average hit 38 mid-task); compare old and new back to back, not against an earlier measurement.
