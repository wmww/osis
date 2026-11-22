# rows-exact
> Summary: Workflow notes from moving the history-row debug check off the per-transaction path.

- A plant's "before" run needs the base tree: mutate.py builds from the working tree, so measuring a plant before and after a change means a wip commit, `git checkout <base> -- files`, a run, then restoring. Run every "before" batch (default tests and properties) first, before editing.
- Each mutate.py batch locks the tree for its build (5-6 min here): editing a planted file meanwhile mixes the edit with the plant. Notes can be edited during a build, code cannot.
- mutate.py's per-row failure list is every failing test (960 names for a plant breaking dating everywhere); the per-mutant logs plus a script counting panic messages by check told which check caught what.
- A whole debug check deferred to the end of history loses faults a later step heals within the history (two plants, each caught before only by one gate-size property): the per-step trigger has to be defined independently of the code it checks, so a plant in the code's own decision still fires it.
- Single-threaded `tools/icount` of osis-engine lib and `it` take 14-28 min each here (four ran beside mutate batches): start them as soon as a binary is copied aside, never wait on them in sequence.
