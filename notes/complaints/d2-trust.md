# Complaints: d2-trust
> Summary: Workflow snags met making first received the rule of roles-model `paths` (stage D2).

- A text edit by `s[:a] + new + s[b:]` with `b = s.index("### What it gives")` duplicated a third of notes/write-path-design.md: the heading occurs twice and the first is above the section replaced. Search the end marker from the start marker (`s.index(x, a)`), and read `git diff --stat` after any scripted note edit.
- One hold of nine 3,000-world controls plus both story searches at 10x ran 7,661 CPU-s against the hold limit of 5,060: split a 10x batch into a hold per search.
- A rule refinement added between two long holds (recording a lowering only where it took its hop down) looked right on the two worlds it was written for and failed the story at gate size, found only after its 10x hold had started: run the gate-size search before queueing the 10x one, in a hold of its own.
- `rg ... | cut -c1-700` on a story search's `paths:` line cuts off `failing checks`, which is printed last: pick the field out with `rg -o 'failing checks \{[^}]*\}'`.
- The story's nodes get an edge write as evidence at the tick it is made, whatever their receipts say, so "received in one update" cannot be set up by editing `recv`: `Sim::joins` (a node's first sync) is the way to a node with no order.
