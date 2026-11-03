# simplify-sync
- A fresh worktree's first tier 1 took about 9.5 minutes under load 30 (cold test build), against "about 40 s warm".
- A Bash call running two clippys in a row went to the background at 180 s without being asked: the second (`clippy-net`, a cold build here) took 3.5 minutes.
