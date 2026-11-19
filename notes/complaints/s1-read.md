# s1-read
- A full `cargo test -p osis-sync` started before an edit to a test file builds whatever is on disk when cargo reaches that crate: three failures in the first run came from my own mid-run edit window, not the code. Edit only after the run's build line.
- The brief's literal reading of decision 2 ("an act is not sent on a connection that is full") inverts spec/sync-judgement.md §3 (at a full source a carrier it lacks counts as held; role entries skipped): built as the spec says, the act owed only because full goes only where the source told full.
