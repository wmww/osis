# thin-client-rotation
> Summary: footguns met while fixing rotation's listener gap.

- The by-hand QUIC test's "old address never answers" assert passed for the wrong reason: the closed old endpoint's CONNECTION_REFUSED is also `Network`, same as a key mismatch. Asserts on a broad error class can hide which path answered.
- `rotate_peer_address`'s doc promised "listens at once" while the relisten was async in the driver; nothing in the default suite dialed right after a rotation, so the gap only showed over real QUIC.
- Review: `rotate_peer_address`'s doc claimed it "listens" on every path; the driver's relisten failures (Reach retried later, `listen` URLs left down) answer the marker all the same. A "returns once X" doc needs the failure path stated.
