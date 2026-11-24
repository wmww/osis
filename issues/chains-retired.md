# The chained pass has no reader
> Summary: spec/permissions.md §4 judges by evidence along stated paths and has no chained writes; osis-perm still computes chained-ness and the models keep chained sets, each site marked `Interim (issues/chains-retired.md)`, read by nothing in the engine.
> Priority: normal
> Tags: permissions, tests

What stands in, to delete together:
- osis-perm `paths`' chained pass (`Paths::is_chained`, `Timeline::is_chained`, walk.rs's chained levels) and its tests (osis-perm `paths::chained`).
- The models' chained sets (roles-model `paths`, held-model `evidence`, `spec_open10`). After a model change run osis-perm `paths::` and osis-engine `evidence::` differentials.
- Test comments citing chains (osis-engine `facade`, `validity`).
