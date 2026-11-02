# Store row names link versions; a class step can still show a drop
> Summary: Store rows are padded (Padmé, units at least 512 B; notes/local-store.md, Row padding), so a freed page's old version shows only its length class. Left: row names (`u slot ver`) are plaintext and link every lingering version of a slot in order, and a drop that moves a page across a class boundary (probability about dropped bytes / class width) still shows one class step. No forensic test checks row lengths yet.
> Tags: security, store

## Left
- Row names link versions. Fix: name each row by a hash of its own (fresh, per-version) key; the parent holds the key, so reads stay direct. Journals and superseded-row deletes already carry names; scans by `u` prefix would go.
- Class steps: with linked names, an attacker compares adjacent versions; a d-byte drop crosses a boundary with probability about d / width (32 B at 512 B, 256 B at 4 KiB). Unlinkable names remove the pairing; padding table pages to `page_max` would remove the step for pages (+108% unit bytes measured on engine tests).
- Forensic test (`core/store/tests/it/shred.rs`, `core/node/tests/it/shred.rs`): the lengths of all historic rows of a slot around a shredded drop of a small entry are equal, or differ by at most one Padmé class.
