# s3-lastadmin
> Summary: Workflow notes from the last-admin build.

- A foreground `cargo build -p osis -p osis-cli` after an engine change outran the Bash tool's 120 s default and was moved to the background mid-run; builds of the osis crate after an engine edit go `run_in_background` from the start.
- The engine's `Demotion` struct is built by literal in about 280 places (tests in six crates), so a flag on one demotion costs a sweep; the adminless mark went in as a scoped engine flag (`Engine::leaving_adminless`) instead.
