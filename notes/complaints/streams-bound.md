# streams-bound
> Summary: workflow notes from bounding Known/crossed and keeping stamp verdicts.

- The underlying store stamps every local row write, so a "quiet" write-back of a cached verdict into an entry row still moves every memo reading that entry (caught only by keep::a_taken_inbox_blob_is_taken_once and read::a_first_start_after_a_session_commits_the_same_at_n_and_10n). Worth a line in notes/sync-store.md for anyone tempted to memoize into rows from a read path.
- Ran a background `cargo test -p osis` while editing osis-sync sources: cargo picks up whatever state the files are in when it reaches the crate. Keep edits out of the tree while a run builds.
