# keel-t-held
- One custody seed replay is ~4 min of rebuild per debug edit to tests_custody.rs (the lib test binary relinks whole); debugging by eprintln in the harness is slow.
- The custody harness read t's secrets with `RoleEpochs::secret` (checked only) while its comment said reading-only ones count: `secret` vs `reading_secret` is an easy mix-up.
- LocalPeer `sync`/`deliver` hand commits over unwrapped, so a test of whether a node can read a write must seal it (`lp.sealed` + `deliver_sealed`); a plain-delivery test passed with the fix undone.
- `KEEL_UNDO= cargo ...` (empty value) still sets the var: env gates on `var_os().is_some()` fire on it.
