# g-outside-5
- osis-sync's differential has two bare-engine references (`history::reference` and `note_gone`'s incremental `Quiet`); fixing one left every history "gone" through the other, with the same symptom (the model reads nothing). Grep for `Peer::new_bare` in a harness before trusting one fix.
- `eprintln!` debug inside a passing test is captured: a mismatch probe needs `--nocapture` or a panic, else a grep count of 0 means nothing.
- A `tools/heavy` all-core run waited about 10 minutes for another agent's hold; the run itself took about 5.
- The sim harness (core/test/sim) handed commits whole and judged quiescence as "every node holds the same parts", which the outside-the-closure rule breaks for any two accounts; the brief's state list did not mention sim-sweep, and its every scenario was red on the branch. A 15-seed sweep is about 130 CPU-s: over `tools/heavy --short`'s cap, so it needs `tools/heavy` (I ran one unlocked by mistake).
