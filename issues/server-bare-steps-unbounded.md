# Bare steps past the byte caps are bounded only by the Register rate
> Summary: a child step is never refused for a storage cap (a refused rotation keeps a removed member's keys valid at that server), only its claim set is dropped. So a stranger with its own labels (up to `max_labels`) can keep adding ~300 B steps past `max_bytes` at `registers` (600/min) per label, kept for good. Bandwidth-bound disk growth past the operator's cap. Low-medium.
> Tags: security, server

- `BackendStore::push_step` (core/server/src/store.rs): past `cap_bytes`/`max_bytes` the step is kept without its set; steps (`S`, `V`, `W` rows) are never dropped.
- Any bound must not be exhaustible by outsiders for an honest label (so no node-wide pool of step room), and must not stop a long-lived label from rotating (steps are kept for good: a lifetime per-label count fails at infinity).
- Directions: a per-label over-cap step allowance refilled slowly (rotations are rare; one step suffices for a removal), node growth then bounded by `max_labels` × allowance rate; or let servers forget steps below the newest a member could still need (path walking after `MEMBERSHIP_KEEP`, spec/sync.md §5 Claim) so a label's steps are bounded by rotation cadence.
