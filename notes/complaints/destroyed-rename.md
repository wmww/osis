# destroyed-rename
- A concept rename with ~1600 hits of a common word ("end", "ended", "ending") has no mechanical path: about half the hits are other senses (grants, edges, streams, passes, links, shared-set members). Classifying line by line with a small script (apply a word substitution only to chosen lines) was the workable route; global phrase rules produced grammar slips ("t destroyed by release") that needed a pass by hand.
- `git grep -c` piped through `xargs sh -c` to count per file was slow on this repo; one `git grep -n` into a file and `cut | uniq -c` was instant.
- Review: the local `main` ref lagged origin/main (four commits, then three more during the gate), so "rebase main" was stale; rebased on origin/main twice. The gate's selection base was the stale local main.
- The gate does not run TLC for an edited model (it lists the cfgs as "selects nothing"); the reviewer must remember `tools/heavy core/test/tla/run.sh <module>` by hand.
