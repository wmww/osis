# Ephemeral data: one state system for an app
> Summary: Tracking issue for ephemeral data (in-memory things and schema-declared aspects, local or synced, signals folded in as event aspects). The design is notes/ephemeral.md, with a five-step plan; nothing built yet. Waits on the owner's answers below and on the commit-query API work.
> Tags: api, node, sync

Design and plan: notes/ephemeral.md (owner direction of round 13 recorded there).

## Owner questions
- **Ephemeral placements.** The design makes a group op on an ephemeral item ephemeral too (an in-memory overlay that becomes a durable `/group` write when the item persists). The literal direction ("a group persists through its `/group` items") would instead write the group durably and leave a ghost tid in it after a restart, and a durable entry per synced ephemeral thing. Recommended: the overlay. A group op on a durable item still persists the group.
- **`MAX_LEASE` = 5 min**, a protocol constant: how long a value can outlive its writer when no `Left` arrives (hostile server, half-open connection), against one re-send per live writer per label every 2.5 min.
- **Requirements wording** (spec/requirements.md): the Ephemeral data section, exempting ephemeral state from "Deterministic" and "Convergence", and the Generality rule for presence (ephemeral aspects instead of expiring writes). Exact edits in notes/ephemeral.md, Deleted with this design.

## Status
- Steps 1-5 of notes/ephemeral.md: not started.
