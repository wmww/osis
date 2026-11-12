# forged-chunk-list
- Reproducing the forgotten-introducer case needs two `TOMBSTONE_LIFETIME` advances plus a 2.5 MB value so no snapshot triggers; no smaller knob makes own-replace-only histories reachable in a test.
- `Engine::blob` reads a whole blob; a prefix check wanted only `LINKED_PREFIX_MAX` bytes and had to go through `run` + `tx.blobs.read`.
- Review: the rebase onto net-6a conflicted in `kdf.rs` `PURPOSES` (both added labels); one list of purposes edited by every crypto branch conflicts every time.
