# fast-harness
- `wt claim` worktrees: a kit test that builds 600 commits by helper (`create_note`, `name`, `add_tag`) took 50 s; batch them in one `Write` in tests.
- `tools/policy.py kit` crashes with a Python traceback (FileNotFoundError); the form is `tools/policy.py libs/kit`.
