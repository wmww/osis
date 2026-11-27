# Dial candidates: empty URLs, a dropped own entry, no caps
> Summary: Gaps in what a node dials: a key known only by an empty `peer://` URL is dialed every `REDIAL_MS` with LAN off; a node's own `dial.0` entry another writer dropped is written back only at its next listen; and the `dial.0` lists of read things add candidates with no cap, so a hostile writer can point many nodes' dials at a victim.
> Priority: low
> Tags: sync, transport, security

Dialing is by `dial.0` on any thing (notes/accounts-switch-brief.md, What the spec says).

- **An empty `peer://` URL** (a sharer's hint from a node with no relay and no global listener, a node listening on loopback) is dialed every `REDIAL_MS`, failing at once (`unreachable: peer://`), and tried first for a peer known at both. "None means LAN only" (spec/sync-transport.md §3), so with LAN off it names no route: a URL with no route is no dial candidate, or ranks after any URL with one.
- **Own entry written only at listen**: `Engine::publish_reach` runs after a listen and at `rotate_peer_address`. Where another writer may write the list (an account's `dial.0`, which every node of it writes), a dropped own entry stays dropped until the next listen. Fix: the node follows its own entry (an `Effects` over the lists it keeps an entry in) and writes it back when missing.
- **Unbounded candidates from other writers**: `Engine::dial_peers` takes every entry of the `dial.0` of a read S's things; only `Why::Discovered` is capped (`DISCOVERED_KEEP`). A hostile writer can list many keys at a victim's URL, so every node reading the thing dials the victim (each key once per `REDIAL_MS`, at most `MAX_PEERS` at once). The memory goes under issues/resource-limits.md's node-wide budget (no per-subsystem caps); what is open is a rule for which candidates are worth dialing.

## A hint no node answers
A dial hint to a peer that never answers storms the sim harness (about 2000 deliveries) instead of backing off (seen writing the signal dial-hint test).
