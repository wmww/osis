# gate-comments
- The gate's instant checks run past their `gate.checks` wall share (10 s against 5 s at load 8): tools/gate_select_test.sh alone takes 4-6 s (each case a fresh repo commit plus a `--plan` gate run). Not new with this branch (main's copy takes about 4 s); the share is tighter than the step.
- A comments-only probe in osis-base pushed core clippy over its share (44 CPU-s, 15 s): every crate above it re-lints. Expected for a low crate; the share is set for a top-crate edit.
- Testing the comments path end to end needs a base other than HEAD: `--base HEAD` means "everything". A wip commit plus `--base HEAD^`, then `git reset --hard HEAD^`, worked.
- This branch's gate: instant checks 18 s wall at load 14 (share 5 s); this branch adds about 3 s of it (tools/gate_paths_test.py judges sync-spec's 251-file sweep, about 1.5 s, and 9 more selection cases).
