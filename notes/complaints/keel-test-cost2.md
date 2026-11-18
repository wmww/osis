# keel-test-cost2
- cpuprof's stacks are unreliable for spawned threads and deep frames (gimli, `String::write_str` and `HashMap::insert` shown as callers of unrelated work): a harvest "hot spot" it pointed at moved nothing when fixed. Confirm a suspect with `tools/icount` on a variant (an env-gated skip) before changing code.
- A sync test's world fixture (`world_of`) is copied within a process, so building two worlds in one test costs one; only pertest counts a fixture once per test. Check `copying::cached` before restructuring a test to share a world.
- Finding which commit grew a test took a second worktree and a build per commit (5 min each, cold target): a scripted loop over a commit list in the background worked; bisect in two passes (every 5th commit, then the window).
