# client-port-fixes
> Summary: workflow notes from the (b) code-review fixes.

- Rebasing over client-port-wait conflicted in core/osis/tests/it/port.rs (both appended tests); the auto-resolution of the shared suffix (`n.close().unwrap(); }`) attached it to my block and left their test unclosed. Check the end of each side's block after resolving appended-test conflicts.
- osis's lib has `test = false`, so a client-internal mechanism (nonce stamping on the I/O thread) cannot get a unit test; the integration test catches the bug only when the race window is widened (probe: sleep between taking and sending the nonce).
