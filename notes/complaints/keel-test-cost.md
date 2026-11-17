# keel-test-cost
- `tools/pertest.py run` takes `tools/heavy` itself: wrapping it in `tools/heavy` as the brief said would refuse (nested).
- `pertest.py run` removes `OUT.bins/` at the end: profiling a test it flagged means building its binary again.
- pertest runs each test as its own process, so every test pays its process's cached fixtures (`world_of`, `LocalPeer::cached`): most of a median osis-sync or rotation test's count is its fixture, which a whole-binary run builds once.
- Main failed 7 default tests outside the core crates (osis-cli 3, osis-sim 3, osis-chat 1: "would be held by nothing", a commit count 14 against 15, a missing field), not in known_failures; nobody gates those crates per branch.
