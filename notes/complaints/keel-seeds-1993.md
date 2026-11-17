# keel-seeds-1993
- A differential shrink runs under the seed runner's 600 CPU-s timeout, so a full-size shrink stops at 28-40 steps; continuing it meant a scratch test calling `harness::shrinking` on the printed script. A way to resume a shrink from a printed script would save that.
- Both seeds stopped failing once 72a51952d landed mid-task: about an hour of shrinking and tracing went on a bug already fixed. Worth replaying a seed on the newest origin/main right before digging in.
- An order-harness test pinned a pack count that relied on the ms-floor leak (same-ms base writes escaping a default floor); its count moved with the fix.
