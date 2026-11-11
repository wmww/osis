# possession-role
> Summary: workflow notes from the possession-at-role-needed branch.

- Two test helpers named `rotate_unchecked` (tests_members, and the one wanted for tests_possession): the engine's `rotate_leaving_out` test helper swallows commit errors (`let _ =`), so a rotation the writer rules refuse silently makes nothing; a test relying on it can pass vacuously unless it counts the commits made.
- A first design (a read-alone rotation proving the holder at write in its read keyset) passed every engine test and 1000 rotation_holds seeds; only osis `sharing::team_left_out_by_a_sealer_reading_none_of_it_reads_again_spec_crypto_4` caught that certificate-only nodes find staleness through keyset proofs. The engine has no small test of that dependence.
- Review: I ran `git checkout possession-role` in the main checkout by mistake (to read files) before claiming a worktree; reverted at once. Reading a branch's files is `git show <branch>:<path>`, no checkout needed.
- Gate limits: `gate` (299 s) and `gate.hold` (241 s) wall limits sit far below the ~30 min CLAUDE.md states for a full gate; this run (all stages pass, load 12-30) took 2070 s and flagged 6.9x. The limits look miscalibrated (perhaps set from a gate selecting few crates), not a slow branch.
