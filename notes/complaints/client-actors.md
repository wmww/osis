# client-actors
> Summary: Mishaps while building client port step (c).

- `notes/client-port.md` said the engine checks the acting actor's rights and receivers judge the actor's grants; `check_authority` and validity judge the author node only (`act_as` sets a header field). Writing the check took less time than finding that out.
- `osis/tests/it/port.rs` `Raw` runs the link's tasks only inside `block_on`: a `send` without a later wait never left the process, so the first "queued request" test passed vacuously; a fix-disabled probe showed it. `Raw::pump` now.
- A probe script's `subprocess.run(timeout=)` kills cargo but waits on the test binary's pipes: a hung test hung the script. Use `timeout -k` around cargo with output to a file.
- A panic inside a test holding a node whose dispatcher callback is blocked on a channel hangs on unwinding rather than failing.
- One hang of `secret_hash_and_rotation` seen once, in a run with `client_of`'s hash compare disabled, not reproduced (ptrace is blocked here, so no stack): notes in the report.
- Review: `Reader`'s checks read as complete, but `groups.0` and `Scope::Group` went round them, and `check_confined` missed what `undo::unmake_ops` and `place_plan` write on top of the mutation it saw. A writer through several layers needs the check at the last one, or a list of what each adds.
- `localhost::` CLI tier-2 tests are in no per-branch list and two fail on main (issues/cli-localhost-tier2-fail.md): took a main build to tell they were not this branch.
