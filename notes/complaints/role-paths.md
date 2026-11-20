# role-paths
> Summary: Workflow notes from the role-paths branch (role commits stating real paths).

- Comparing the two walks across the engine suites needed a throwaway drop hook in the lib (the adapter lives in `tests/it`, which lib tests and engine drops cannot call); engines dropped in a property's own `Drop` run on an unnamed thread, so the test name came only from a captured backtrace.
- `tools/spec_map.py` reads `notes/a1-spec/permissions.md §2 (…)` in a test comment as a citation of `spec/permissions.md §2`: write draft citations without a parenthesis after the section.
- The engine suites take 3 to 6 minutes each run here; four probe runs of them were the slow part.
