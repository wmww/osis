# Sync rules no test reaches
> Summary: Six sync mechanisms, each added to fix a differential failure, survive being switched off: no default test fails (the whole osis-sync `it` binary, 20+20 convergence seeds included), and hand-written scenarios built to reach them pass too. Each is either redundant (another mechanism covers it: then remove it) or guards a corner no test builds (then write the scenario).
> Priority: normal
> Tags: sync, tests

Each mutation below was applied alone and the whole osis-sync `it` binary run; every test passed. The scenarios named were written by hand to reach the rule (two nodes, contacts, seed 0) and pass with it off as well.

| rule (code) | switched off as | scenario tried |
|---|---|---|
| spec/sync-inbox.md §2 Re-send: an open by a read secret shows a delivery taken only at a current epoch (`inbox/deliveries.rs` `opened_taken`, `Some(e)`) | any read-secret open counts | a reader removed and granted read again, with and without runs between, cut or partitioned between, a failed durable write at each of its first 8 |
| spec/sync-opens.md §3 `changed_at` moves with S's roster (`opens/holds.rs` `c.roles = rc.roster`) | line removed | `flows::a_reader_granted_again_reads_the_write_made_while_removed_spec_sync_opens_3` |
| spec/sync-judgement.md §6 Read and unread move: raised from unread to read opens every held entry (`store/follow.rs` `raised`) | loop skipped | `flows::raised_from_sync_to_read_reads_what_is_held_spec_sync_judgement_6`: S's start parks what did not open and the read-secret settle opens it, so this loop may be redundant |
| an own entry whose commit went with lost access waits for S's read secrets (`store/follow.rs` `waits`) | own entries never wait | `flows::a_writer_granted_again_reads_what_it_held_spec_permissions_3`, also with a failed durable write at each of its first 8 |
| a pending commit's entry is kept as its carrier (`streams/mod.rs` `EngineGround::open`, `Opening::Pends`) | never `Pends` | a reader granted after a writer's removal (three accounts) |
| a place of a shredded S is forgotten before it is read (`streams/pull.rs` `place`, `forget_shredded`) | call removed (`tick` still calls it) | a sync holder removed and granted read while cut off |

For each rule: find the scenario that needs it (`OSIS_SYNC_TRACE` on a differential seed with the rule off, over many seeds if needed: `OSIS_FULL=1`) and write it by hand as a default test; or, if nothing needs it, delete it.
