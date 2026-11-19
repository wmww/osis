# s2-schema
> Summary: Workflow snags met on the S2 brief 4 branch.

- A foreground `cargo build -p osis-engine --tests` passed the Bash tool's 120 s limit and was moved to the background mid-pipe; start engine builds with `run_in_background` from the first call.
- The brief cited a "behaviour table" in issues/external-signals-taken-by-default.md that the issue did not have; which error a refused fire returns had to be read off the engine (`check_role_with`, `write.rs` signal check).
