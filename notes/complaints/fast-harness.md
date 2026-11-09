# fast-harness
- `wt claim` worktrees: a kit test that builds 600 commits by helper (`create_note`, `name`, `add_tag`) took 50 s; batch them in one `Write` in tests.
- `tools/policy.py kit` crashes with a Python traceback (FileNotFoundError); the form is `tools/policy.py libs/kit`.
- The gate failed on `port::a_wait_needs_no_pump...` (issues/port-closed-error.md), not from this branch: a flake in core that the worker never ran.
- Kit tests vary 2-60 s with box load alone (CPU constant; app binary 45 CPU-s); nothing waits. `cargo test -p osis-kit` from the repo root fails ("similar name"): kit is the libs/kit workspace.
