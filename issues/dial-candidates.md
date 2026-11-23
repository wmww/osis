# Dial candidates: empty URLs, a dropped own entry, no caps
> Summary: Gaps in what a node dials: a key known only by an empty `peer://` URL is dialed every `REDIAL_MS` with LAN off; a node's own `dial^.0` entry another node dropped is written back only at its next listen; and a contact's `dial^.0` list adds candidates with no cap, so a hostile account can point many nodes' dials at a victim.
> Priority: low
> Tags: sync, transport, security

Stages A5 and A6 (notes/redesign-plan.md): the dial aspect moves off the account profile (notes/write-path-design.md §3, Contact-only information); take it after.

## A `peer://` URL with no items is dialed though nothing can reach it
A node with LAN off dials a key known only by an empty `peer://` URL (a link sharer's or a grantor's hint from a node with no global listener, a node's own `reach.0` on loopback) every `REDIAL_MS`, failing at once (`unreachable: peer://`); and a dial of a peer known at both tries the empty one first. Noise in `diag`, one wasted dial per redial.

Seen in the dogfood rehearsal (notes/dogfood.md): member B kept dialing A's node (the link's sharer hint, A listens nowhere) every 30 s, and each redial of the shared node (listening on loopback, so its `reach.0` has no items) went to `peer://#KEY` first, then `quic://`. Spec reading: "none means LAN only" (spec/sync-transport.md §3), so with LAN off such a URL names no route; the simplest rule is that a URL with no route is no dial candidate (or ranks after any URL with one).

## A node's dial list entry is written only at listen
`publish_reach` runs only after a listen and at `rotate_peer_address`, so a node whose own `dial^.0` entry another node dropped (`dial::drop_departed`, e.g. it saw the node's fresh entry before its re-pairing) stays undialable by contacts until its next listen.

- Possible only if a node of P can apply a re-paired node's profile write before the role commit re-adding it to D; unverified whether judgement parks that write.
- Fix if real: the node follows its own entry (an `Effects` over the dial list and its `reach.0`) and writes it back whenever it is missing while it is on D.

## Dial candidates from other accounts are unbounded in number
A contact's `dial^.0` list adds dial candidates with no cap on their count; a hostile account can list many keys at a victim's URL, so every node sharing something with it dials the victim, bounded only by `MAX_PEERS` and `REDIAL_MS` per node.

- Sources: `Engine::dial_peers` (each account holding a role on a read S: its whole `dial^.0`, written by its profile's admins). Only `Why::Discovered` is capped (`DISCOVERED_KEEP`).
- Cost per node: memory per candidate, and at most `MAX_PEERS` dials at once, each key once per `REDIAL_MS`; a dial that fails is no amplification beyond one connection attempt per key per 30 s.
- No per-source cap (Tess: no arbitrary per-subsystem memory caps): the memory goes under issues/resource-limits.md's node-wide budget; what is open here is the dials aimed at a victim, a rule for which candidates are worth dialing, not a count.
