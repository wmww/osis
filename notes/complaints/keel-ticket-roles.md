# keel-ticket-roles
- The differential's printed failing script does not compile: it prints `Node(1)` for a `Give` holder, but `harness::script` exports `Holder`, not its variants (`Holder::Node(1)` works).
- origin/main moved under me between a fetch and a comparison run on `git checkout origin/main`, so a "passes on main" check ran on a newer main than my base; rebase before comparing.
- I left a conflicted rebase unfinished (no `rebase --continue`), committed and checked out another ref; the branch ref stayed at the pre-rebase commit. Recovered from the reflog (`rebase --quit`, reset to the commit). Finish a rebase before anything else.
- A test livelocking in a World run hangs `cargo test` silently for minutes; only the libtest "running for over 60 seconds" line tells which.
