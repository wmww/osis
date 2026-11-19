# Sync tests still owed
> Summary: The rebuilt sync's tests still missing: the reference graph's properties with no sync world test, from the old sync's issues, the API tests the rebuild dropped, the simulation set and the scale checks; drop a line when its test lands. Also the dead public items left unused by the rebuild.
> Priority: normal
> Tags: sync, tests

Test conventions: notes/sync-test-harness.md (one harness, one fast test per spec rule cited per tools/spec_map.py, the differential, simulations, scale by counting work at n and 10n; long runs are release checks).

## Reference graph properties with no sync world test
Each needs a sync world (three nodes, contacts or siblings, inbox delivery) unless it says otherwise.
- D's deposit seed is fresh after a node removal: the removed node's deposit to the inbox is refused (an account removal from a thing: engine `flows::removal_refreshes_deposit_seed_*`).

## Scenarios from the old sync's issues
Each readable with `git show e1bafb8ca^:issues/<name>.md` (`refused-memory-entry-holds-label-unsettled` for the one named by sync ID).
- unsettled-judgment-tests: a judgement staged while a fetch is out: a blob losing as needed whose extra delta dropped as covered is not deleted by a node fetching the cover; a body killed by a write the holder lacks stays until its cover is there; a purged delta dropped as covered leaves at once without a carrier.
- must-carry-liveness: deleter and holder judge a part's liveness differently (a later write only one holds): no delete and log-again loop past the bounded once.
- chunk-of-forgotten-commit: a source showing a piece again after it was deleted through the freed set (a lost answer) gets it judged and deleted.
- reader-copy-linked-blobs: a body whose only copies are at readers comes back with its linked chunk, tree-node and page blobs.
- promote-covered-only-deposit: a deposit whose parts a held snapshot carries is not promoted (inbox's act is tested on fake facts; the engine's `promotable` answer is not).
- host-takes-inline-before-owed: a node keeping S unread logs a removal before content announced after it, even when the content's bytes come inline first (spec/permissions.md §3).
- refused-memory-entry-holds-sync-id-unsettled: an ephemeral entry refused for the memory cap holds no deletion or repair judgement of S unsettled.
- relink-queue-lost-at-restart, pass-sources-restart: a restart forgets no chunk repair and drops no source a removal's wait counts.
- pulled-refusal-lost: a refusal of a pulled entry lost with its connection is learned again on reconnect.
- doubted-head-exhausted: a doubted open head whose Behind walk finds no earlier credential still learns the peer's later head without a reconnect.
- stranded-holder-unread: a node holding a thing at sync only sends stranded reports, inbox chains and re-seals with no keyset it does not follow.
- listing-horizon-tests-isolation: a listing past the deletion horizon is checked with an entry the reader cannot judge (another node's card, a role certificate) deleted while it is away.
- lan-replaces-relay-flaky: a LAN route replacing a relayed connection comes up at the first announcement, not its 30 s repeat.
- Counted at n and 10n: dropping F entries past a source's delete rate sends O(F) items in all (delete-resend-past-rate); a write killing one body under purge on replace judges O(1) entries (kill-judges-sync-id-entries); one step flat in things held (sync-step-cost); one connection's flood of inputs delays another source by a few reads (host-hub-stall; sources a transport cannot tell apart stay a stated limit).
- forged-section-at-store (unopened-section-forgery): a reader's blob of a genuine commit with junk in a section a delete-key holder cannot open, planted at a store keeping S unread with a lower blob ID: the store keeps the genuine blob, and a reader opening that section syncing only through the store reads the commit (needs a harness hook placing a hostile node's own entry; the rule is tested at the engine rows and the pure judgement).
- no-server-audit: its 37-row feature table again, with only nodes that sometimes reach each other (no relay, no internet, no node at a fixed address).
- Client port: tracking reads of `role_on`, `holders`, `backlinks`, `profile_of` and `stream` follow a thing at a connected node (tracked-read-port).

## Built, untested end to end
- HN_fallany (a snapshot arriving invalid moves the fall mark as one held valid falling does): the engine's `fall_mark`.
- `Live::fresh` (held blobs handed to `Engine::seal_body`): no World test; a mutation passing none fails no osis-sync test (the engine's `rotation::tests_reseal::facade_*` cover the contract). Cheapest found: a purge of one thing's part of a commit spanning two things, the other thing's section then logged again verbatim.

## API behaviours the rebuild's deletion left untested
Names from `git show 28641727e`; each goes through the facade.
- libs/chat across synced nodes (libs/chat/tests/it has create, edits, purge sets, cursors on hand-carried commits, a chat made, joined by link and relayed over sync; a kick's validity flip: core/osis/tests/it/backlinks.rs): deletes and tombstones reaching a new node.
- Redeem edges (spec/permissions.md §7, spec/sync-inbox.md §6): after a joiner left, a node removal, an expired delivery, a mismatched target, a stalled pull, one refusing peer (old sharing.rs `redeem_*`).
- Cross-node rules other notes list as awaiting sync tests: retention dating (notes/engine-retention-dating.md), destruction (notes/expiry-creation-design.md), paged scale checks (notes/engine-paged.md).

## Simulations still missing
- A granter's account rotation leaves its grant counted at a node keeping S unread (sync-only-chain).
- Connections and shared-set work counted at 10^2 and 10^3 LAN nodes (every LAN announcer is dialed).
- Both ends of a connection agree on each stream join (a check that would have named refused-join causes at once).
- A refreshed ephemeral value (a cursor rewritten before its expiry) read through a node whose clock is before the old value's expiry.
- The rules old sim seeds reached with no small reproducer (member_churn, work_sets, purge_falls_churn, link_race, parts_relay, large_edits), as scenarios, never pinned.

## Scale
The sync-shaped scale checks the deletion removed: notes/test-scale.md, Checks to restore (engine-level ones go in core/engine/tests/it; the old ones are in git at 680a85188 core/node/tests/it `scale`, `growth`).

## Dead public items
Public items the old sync used and nothing calls now (osis-proto `OFFSET_DIAGNOSTIC_MS`; osis-store `log_heads`, `table_len`; osis-transport `recheck_relayed`, `relaying`; osis-sync `status_of`): each is used by a test above or deleted.
