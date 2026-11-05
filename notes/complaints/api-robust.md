# api-robust
- A script appending `.unwrap()` to changed reads across tests met nested calls and calls already unwrapped (`Option`s now behind a `Result`): three runs.
- A background `cargo check` of root then GUI workspace, piped through `grep | sed`, stayed "running" for over 20 min with no cargo process left, and never printed. Run the GUI step on its own.
- Review: CLI `--timeout 0` means no timeout, so a test of a delivering command with it hangs; use `1ms`.
