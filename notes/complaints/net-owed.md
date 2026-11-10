# net-owed
- `Net::tamper` saw every peer frame both ways with no sender, and all nodes draw the same stream request ids, so a test could not single out one link's reply; added `Net::tamper_link`.
- Disabling a fix by prefixing `false &&` to an `a || b` condition only disables `a`: check the disabled run actually fails before trusting it.
- Review: the sim delivers each Send as its own input, so `ServingSession`'s per-input request charge never sees several frames together; a window bug that only a real driver's 64 KiB reads hit stays invisible to every sim test (issues/stream-request-window.md).
