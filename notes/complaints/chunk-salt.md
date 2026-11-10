# chunk-salt
- Checking "fails with the fix disabled" by swapping `core/node/src` to an older commit rebuilds the crate twice (several minutes on a busy box); a test-only rebuild is quick.
- Disabling salt recording entirely made a test hang rather than fail (declined bytes woke a pass that fetched again); a test loop on `net.step()` has no step cap.
- A stray copy of inbound.rs went to the scratchpad root by mistake.
- Review: a hand Fetch injected on a peer link needs an id with `NODE_IDS` set, else the listener's host serving answers it (NOT_OPENED / MALFORMED); cost a few rebuilds to find.
- Review 2: turning bad-hash bytes into an announcement without bytes made a hostile host's fetch answers wake a pass that fetched again: `stream::`/`local_serve::` run hung (no step cap in `net.run`), not failed.
