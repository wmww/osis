# sheave-p1-classes
> Summary: workflow snags from fixing the sync differential's classes.

- **A gate's NEW was main's, twice.** Each gate's random offset drew differential seeds that fail on origin/main as it stands (a removal the harness wrongly counted, a release lost at a restart, an unparked entry), reported NEW against a test-only or oracle change. Telling them apart took a `tools/bin-at origin/main` build and replays by hand each time (about 15 minutes). Would help: the gate replaying each NEW property seed on the merge base's binary and marking those that fail there too as "on main" rather than NEW.
- **A background shrink on `cargo test` rebuilds with the tree.** An edit made while a shrink was starting broke its build and the run was lost. Running long by-hand jobs from a copied test binary (as `tools/mutate.py` does) avoids it; notes/test-harnesses.md could say so where it describes shrinking.
