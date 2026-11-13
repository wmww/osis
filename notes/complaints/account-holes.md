# account-holes
- A seconds-long TLC run (`run.sh account` at 8 workers) waited 30+ min for the heavy lock behind another branch's sweep; reran at one worker unlocked (notes/build.md allows it). The brief said "TLC only via tools/heavy", which conflicts with notes/build.md for small instances.
- `Engine::check` after an open asserts no header is decoded: judging D's epochs (establishment reads names) from `observe_state` at load trips it; compute such judgments lazily, only for entries new here.
