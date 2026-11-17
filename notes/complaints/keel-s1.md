# keel-s1
- Finding which row a census family's extra is takes a probe each time: no test helper names a family's rows (engine `local_census` counts only), so each S1 diff meant a throwaway probe test and a temporary engine scan helper. A `local_rows(prefix)` testing helper would make S1 failures readable.
- The first fix for `bp/` (drop a blob's note when no entry names it) broke two invalid-commit tests: a peer still listing a blob is an owner the store cannot see. The owner of each row family is not written down anywhere one place; issues/storage-owners.md is the closest.
