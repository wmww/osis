# judgment-vectors
- The `.vec` format reserves `pending` (a case with it is skipped by `live()`): an expected-output key named `pending` silently turned every case into a skipped one and the replay test checked nothing until a case count assert caught it. Expected keys must avoid `pending`.
- `order::play` and `Step` were private to order.rs; reusing them meant widening visibility (now `pub(crate)`).
- Review: restoring a hand-edited vector with `git checkout <file>` brought back the committed (pre-regeneration) file, not the working copy; copy the file aside before a spot-check edit.
