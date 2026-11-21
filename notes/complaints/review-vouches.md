# review-vouches
> Summary: Workflow snags met reviewing the prune-vouches branch.

- A concept removed from code leaves remnants across ~40 notes, issues and drafts (`grep -ril vouch` gave 270 lines, most of them other senses: snapshots, addenda, stamps). The review's notes pass took longer than the code review; a worker removing a concept should run the grep and sort senses itself.
- Story move renumbering leaves stale numbers in notes that cite moves by number (path-model-findings, write-path-design, evidence-model-findings): grep `move [0-9]` in notes after a renumber.
- `tools/mutate.py` on roles-model's lib leaves the mutated build in `target/`, so the next plain test run rebuilds the crate: expected, but a minute each time.
