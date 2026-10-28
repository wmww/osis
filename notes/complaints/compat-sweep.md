# compat-sweep
- First background test run wrote its log into a scratch subdir that did not exist yet: the redirect failed at once and the run "passed" (exit 0 from `echo`). Create the dir first; check the log has `test result` lines.
- `grep -o` with `.{0,200}` around a pattern hits ugrep's complexity limit on this box; python `re` works.
- Load 28-30 from other agents during verification: `cargo test-net --tests` (first net build in this worktree) took 9 min, the 30-seed sweep 6.4 min (expected 2.2).
- Reviewer hit the same missing-scratch-dir redirect (claudewait reported exit 0 after 0 s); 30-seed sweep 589 s at load 36.
