# Ephemeral leftovers outlive their entries' charge
> Summary: A memory commit's node-cap charge rides on its label entries; a purged (or expired, not yet covered) leftover outlives them once a right holder deletes the entry at the host, and is then held uncharged until a restart.
> Priority: normal
> Tags: ephemeral, sync, security

- `Engine::memory_charge` counts every held part, leftovers included, but node-sync charges it per entry (`State::charge_memory`, `charge_applied` at apply) and releases it when the entry goes (`remove_entry`). A purge's right holder deletes the purged body at hosts (`pass/delete`, `body_gone`), so every holder's entry leaves while the leftover stays held (a purged leftover never drops as covered, spec/commits.md §5).
- Effect: a writer can write memory commits up to the cap, purge them with one aspect-wide request (all are `writer`-purgeable), and write again; each round leaves one small leftover (stamps, dots) per part at every holder, uncharged, until restart.
- Fix direction: charge a held memory commit by the commit, not its entries (while it is held, whatever its entries), recomputed when a part strips or drops. Node-sync's memory charging is being reworked (one-peer-3h2); do it with or after that.
- Test: write, purge and delete at the host in a loop; the label's charge stays at least the leftovers' `memory_charge`.
