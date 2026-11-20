# list-cuts
> Summary: Mishaps and slow spots met on the list-cuts branch (a cut's list per cut; list entries per leaf).

- One shell call doing a python edit, a build, a copy and a `tools/heavy --short` run was auto-denied by the harness as a whole: split edits, builds and holds into separate calls.
- Five perm test files and two engine test files each build `EdgeWrite`s by hand with their own list helper; an input type change touches all of them (`paths::whole` now serves the perm ones).
- `tools/mutate.py` on `List::names` was caught only by the content differential: the walk reads a leaf two ways (`List::names` for edge-class drops, the `named` index per (commit, thing) for content), so a plant on one leaves the other's tests green; plant both sites.
- The purge oracle hard-codes "X's grant is stamped 1" per path; a rule that reads the grant's millisecond (a list gives no role the path never gave) moved it and showed up as 114 `purge kept` failures before the oracle was read.
