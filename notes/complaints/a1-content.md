# a1-content
> Summary: Mishaps met on A1 step 3b (paths content and vouches).

- Open numbers in notes/a1-spec/README.md collide across parallel branches: a1-paths took Open 16 on main while this branch used it; renumbered to 17 after the rebase. A per-branch prefix or a claim line would avoid it.
- `tools/mutate.py` with an OLD that is the receiver of a method chain (`path && tl.parts_of(x)`, then `.iter()...`) or that sits inside a closure argument reports "does not build" without saying why in the table; plant whole expressions.
- A control that spans two sites (`-facts`, `-purge-contains`, `-first-applied`) cannot be one mutate.py row: probed as hand edits on a wip commit.
- The perm `it` binary cannot run under `tools/cpuprof` (documented): finding why a test got slow took timing runs of the copied binary per test.
