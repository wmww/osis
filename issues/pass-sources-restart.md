# Complete-pass sources are forgotten at a restart
> Summary: `peer_received` and `peer_passes` are memory only, so after a restart a label with hosts completes at its hosts alone, without the peers it was received from before the restart: narrower than spec/permissions.md §3 ("every peer it received the label from"). Hostless labels are covered (they wait out `peer_pass_wait_ms` from the start).
> Priority: low
> Tags: node, sync

core/node/src/sync/deliver.rs `label_passed` waits for the sources in `peer_received` (notes/peers.md Complete passes). Both maps start empty at each start, so a node that received entries of L from a peer P, restarted, then applied a role commit of L's actor re-seals or unties after its hosts pass, while P may hold entries the hosts lack. Only a peer holding entries the hosts lack matters.

Options:
- Store the sources (per label: own nodes and known accounts, as the memory maps are bounded); pass ends stay memory, so a stored source holds the pass until it passes again or the wait ends.
- Until `peer_pass_wait_ms` after the start, every label with a peer source ever recorded waits (needs the stored set anyway).
- State the limit in spec §3 (a restart forgets peers).
