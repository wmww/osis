# judgment-vectors
- The `.vec` format reserves `pending` (a case with it is skipped by `live()`): an expected-output key named `pending` silently turned every case into a skipped one and the replay test checked nothing until a case count assert caught it. Expected keys must avoid `pending`.
- `order::play` and `Step` were private to order.rs; reusing them meant widening visibility (now `pub(crate)`).
- Review: restoring a hand-edited vector with `git checkout <file>` brought back the committed (pre-regeneration) file, not the working copy; copy the file aside before a spot-check edit.
- Checking whether a pinned seed's history judges alike under another setup seed needs relabeling (commit IDs by pack index, things and peers by role) and ignoring roster order (tid byte order) and setup commit order (seed-dependent); a throwaway probe test did it.
- Grants with `until`/invite through the engine flow pull in secrets rotations: one invite case is 48 KB of bundle.
