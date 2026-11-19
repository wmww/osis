# g-outside-3
- origin/main moved mid-task with a fix I had also made (ThingsFeed's clone): fetch before fixing anything outside the branch's area.
- The engine harness's hand deliveries (`lp.packages(i)`, `engine.package(id)`, `common::reader`, `flows::spread`, the order harness's packs) each delivered commits whole; every one needs moving to sync-ID delivery separately. 116 `.packages(` and ~250 `.package(` call sites: a grep for them is the work list.
- `copies::a_copied_world_goes_on_as_the_original` compared `: follows` counts, which `memo::Quiet` makes depend on writes on other threads (nondeterministic under a parallel run).
