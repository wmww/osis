# Dial candidates from other accounts are unbounded in number
> Summary: a contact's `dial^.0` list and grant hints in inbox blobs add dial candidates with no cap on their count; a hostile account can list many keys at a victim's URL, so every node sharing something with it dials the victim, bounded only by `MAX_PEERS` and `REDIAL_MS` per node.
> Priority: low
> Tags: sync, security

- Sources: `Engine::dial_peers` (each account holding a role on a read S: its whole `dial^.0`, written by its profile's admins), `Inbox::dial_hints` (one per inbox blob held, so up to the deposit budget). Only `Why::Discovered` is capped (`DISCOVERED_KEEP`).
- Cost per node: memory per candidate, and at most `MAX_PEERS` dials at once, each key once per `REDIAL_MS`; a dial that fails is no amplification beyond one connection attempt per key per 30 s.
- Likely rule: a cap per account on keys taken from its dial list (its nodes), and per granter on hints; past it the rest are ignored. Needs a number that passes notes/arbitrary-values.md.
