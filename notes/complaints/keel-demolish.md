# Complaints: keel-demolish
> Summary: Footguns met while demolishing the group/inbox/lifetime machinery for the reference graph.

- Pruning by compiler error (delete the fn enclosing each error) is fast but also deletes callers that should have been edited: it took the sync harness's `play`/history step once. Edit shared harnesses by hand first, prune leaves only.
- A note-rewriting script that normalized runs of spaces destroyed list indentation across notes; repaired by diffing against HEAD. Never normalize whitespace in a bulk prose edit.
- Many tests of surviving features (history-less grants, copies, backlinks, references) set up through deliveries or groups, so they went with the demolition; lanes rewrite them, the coverage gap is real until then.
- Main deleted `tools/dead_pub_allow.txt` mid-task: a rebase conflict on a file that no longer exists; take main's deletion.
- CLI integration tests run the binary path at runtime, so `cargo build --all-targets` passes while they call removed commands; grep the test strings for removed command names.
