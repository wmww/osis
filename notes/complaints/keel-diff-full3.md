# keel-diff-full3
- The brief's "seed 88 regressed with 0bcee5459 (states stored as bodies)" was wrong: a probe disabling body states still failed, and binaries of 6ef8166b2, 207951fd6 and 0bcee5459 showed the full seed failing from 207951fd6 (own things released whole), while its shrunk script failed on all three. Bisect with a binary per commit, and check the shrunk script at the good end too: it can fail where the full seed passes.
- `var_os("OSIS_PROBE_X")` is `Some` for `OSIS_PROBE_X=` (empty), so a `for v in 1 ""` toggle loop runs the probe both times.
- The trace cuts lines at 400 chars: a whole listing (which blobs a source lists) is not readable from it; probing the store (entry, tombstone) from the harness check was faster.
