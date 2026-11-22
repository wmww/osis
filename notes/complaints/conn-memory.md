# conn-memory
- The workspace forbids unsafe, so no counting allocator can measure what a test holds; RSS (`/proc/self/status`) is the only gauge and too coarse below hundreds of KB.
- A stranger's session at node level needs Hello, then a Prove of nothing, then NoRecord (a Resume from an unproven dialer is refused, NoRecord before Prove is Malformed): took three traced probes to learn.
- A max-size filter (2^22 entries) costs about a second per decode in debug: a test reaching `IN_BOUND` with filters alone runs a minute; partial frames reach it cheaply.
