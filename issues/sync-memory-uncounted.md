# Sync memory the caps do not count
> Summary: osis-sync's memory caps count what an ephemeral entry and tombstone hold in the store's memory part, but not a removal event left without a tombstone (give-way, a source gone: an hour each), nor other modules' per-entry memory (streams' `Known`, follow's parked set); the memory log's per-member and per-tick reads are uncounted map work.
> Priority: low
> Tags: sync, security

Built: notes/sync-store.md Caps and policy (the memory part counts what it holds, `entries::overhead`).

- An entry removed untombed (give-way, its source gone) leaves its memory log removal event (`memory::REMOVAL`, about 0.4 KB) for `MAX_DRIFT`, charged to nothing: a peer cycling entries through give-way keeps up to its rate times `MAX_DRIFT` of events past the cap. Charging the event to S until the sweep (or serving no removal event for an untombed removal) would close it.
- Per ephemeral entry, streams keeps presence and refusals in `Known` per source, and follow keeps a parked entry per awaited value: neither counts toward the memory caps, so the caps bound the store's memory part, not the node's memory per entry.
- The memory log is plain maps (`store::memory`): moving it into the memory store as rows (so `Store::memory_held` sees it whole) made two tests count reads the maps hide: `Streams::ephemeral` reads each listed member's log at a join (one read per member at an idle reconnect, `idle::an_idle_reconnect_sends_reads_and_judges_the_same_at_10n_spec_sync_streams_4`) and `Streams::served_busy` reads the events past `mem_mark` at every tick while a log naming no position holds them back (`streams::ephemeral_entries_held_back_are_not_read_at_every_tick_spec_sync_streams_4`). The work is there with the maps too; listing only the members `memory_since(min mark)` names would end the first, a busy set kept per mark the second.
