# s1-last
- tools/mutate.py edits the source in place for the length of its build: no other edit in that crate may run meanwhile, so each mutation run stalls the worker for a build (about 1.5 min here). A copy-tree build would let work go on.
- The streams test harness's `leave` sent `Leaving::Connection` with a connection source over a record-kept pull: a combination the product never produced, so two tests asserted a path no node takes; they were moved to the product's release and take.
- Separating two pieces that touch one file (inbox/mod.rs) for two green commits meant hand-restoring the earlier text; `git add -p` is not available here.
