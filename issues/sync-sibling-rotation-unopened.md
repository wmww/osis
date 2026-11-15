# A sibling's concurrent removal never takes effect at the other sibling
> Summary: Two nodes of one account each remove a node while apart; after the heal each holds the other's removal commit whole, yet its edge write does not take effect (the other's removed node stays in D's roster) and its D epoch is not established, so the other's P rotation, wrapped under that epoch, never opens: a device removal is silently undone. Sync delivers everything; the cycle is in the engine's judgement.
> Priority: critical
> Tags: engine, security

Shape (osis-sync `duties::sibling_removals_apart_both_hold_through_sync_spec_permissions_3`, ignored until the engine fix): four siblings, nodes 2 and 3 off, nodes 0 and 1 partitioned; node 0 removes node 2, node 1 removes node 3 (`demote` on D: the removal commit R with D's rotation, then P's rotation Q); heal, run, pass deadline, run.

What node 0 holds after the run (node 1 is symmetric):
- R: held, applied, not pending, its one blob with parts {0,1,2}, not a copy; reopening its entry gives `Duplicate`. Yet `roster(D)` still lists node 3 as admin, `departures(D)` lists node 2 alone, and D's epochs hold only node 0's own n=2 (node 1's n=2 is absent from the map, not even unestablished).
- Q: its blob and entry are in the store under the account's sync ID, entry wrap under node 1's D n=2; `open_entry` gives `NotOpen` (S's read secrets at node 0: its own n=2 only).
- Ingesting R alone by `ingest_with_lists` (during the partition, or with the removals 5 ms apart) gives the same state as sync: so the sync path does not diverge from plain ingest.
- Ingesting Q's plaintext by hand: Q applies, node 1's n=2 is then established (held D epochs n 0, 1, 2, 2), departures cover both, and Q's entry then opens (`Duplicate`).

So R's write and R's epoch count at node 0 only once Q is held, and Q reaches node 0 only under R's epoch: nothing delivery can carry breaks it. spec/permissions.md §3 (Nodes of P) makes the removal count "wherever the rotation does" and encrypts Q's seed under R's D epoch; nothing there says what Q's entry wrap is under, and the engine's `wrap_secret(D, Some(Q))` picks R's epoch, which a sibling holding R alone cannot open. Two ways out, both engine: wrap Q (its role parts only; the seed stays under R's epoch) under an epoch a holder of D held before R, or let R count and establish its epoch without Q at a node of P. The fix belongs to the engine's judgement of a sibling's concurrent removal and rotation (Fathom's fork-sides work).

Also seen: with both sides' commits handed over by `ingest_with_lists` before the heal, the run after the pass deadline never settles: each node, on the other's newest commit, writes another (a merge war at one world ms, a new commit per delivery, hundreds within minutes). The one-way hand-over in `a_rotation_owed_by_the_account_is_made_at_a_pass_end_spec_permissions_3` settles. A fix must leave concurrent merges settling to one.

Once fixed: drop the `ignore`, and let that pass-end test carry node 1's commits by sync instead of handing them over.
