# Forgetting lost things reloads node sync's records without the memory class
> Summary: `SyncEngine::forget_lost` (core/node/src/sync/deliver.rs) reloads `State` from the store keeping only `mem_log`: every memory entry record goes, under labels still synced too, while the engine keeps the memory commits they are about. A holder then holds commits it never places again (a reader alone holding a value keeps reading it while others read none), the class `State::reload` fixed for `restart_in_place`.
> Priority: normal
> Tags: ephemeral, node

- The relist from the start (`stream_restart_known`) brings back records of entries a peer still lists; one listed nowhere (the host and its writer restarted meanwhile) stays held with no record.
- Likely fix: `State::reload(engine, &old)`, then drop the memory entries under the forgotten labels (beside `mem_log.forget`) and those whose commit the engine forgot with the lost things. Needs a node test: a reader losing access to one thing while alone holding another thing's ephemeral value under a label it keeps.
