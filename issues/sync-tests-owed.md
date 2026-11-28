# Sync tests still owed
> Summary: The rebuilt sync's tests still missing: reference-graph properties with no sync world test, scenarios from the old sync's issues, API tests the rebuild dropped, simulations and scale checks; drop a line when its test lands. Also public items only their own tests use.
> Priority: normal
> Tags: sync, tests

Test conventions: notes/sync-test-harness.md (one harness, one fast test per spec rule cited per tools/spec_map.py, the differential, simulations, scale by counting work at n and 10n; long runs are release checks).

## Reference graph properties with no sync world test
Each needs a sync world (three nodes, contacts or siblings, inbox delivery) unless it says otherwise.
- Security on a recording world (`w.record`; the old metadata and shred modules are in git at e499872aa^ core/sync/tests/it): a node keeping S unread holds in clear, live or overwritten, no value, map key, content or core AK, role secret, or writer's node tid or signing key, and every blob it keeps has a Padmé length (by hand: what an attack on its whole device decrypts holds none of them but the core AKs its own things carry); a purge reaching a reader while away, and a dropped blob's wraps and key row (one sync ID or several), leave nothing the forensic attack recovers; a crash at every write of sync's forget (notes/test-security.md).
- Across a node removal: a reader outside the account keeps reading its writes, and the removed node's deposit to the inbox is refused (the deposit seed is fresh: engine `flows::removal_refreshes_deposit_seed_*`).

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
- stranded-holder-unread: a node holding a thing at sync only sends stranded reports and re-seals with no keyset it does not follow.
- listing-horizon-tests-isolation: a listing past the deletion horizon is checked with an entry the reader cannot judge (a certificate copy) deleted while it is away.
- lan-replaces-relay-flaky: a LAN route replacing a relayed connection comes up at the first announcement, not its 30 s repeat.
- Counted at n and 10n: dropping F entries past a source's delete rate sends O(F) items in all (delete-resend-past-rate); a write killing one body under purge on replace judges O(1) entries (kill-judges-sync-id-entries); one step flat in things held (sync-step-cost); one connection's flood of inputs delays another source by a few reads (host-hub-stall; sources a transport cannot tell apart are one source to it).
- forged-section-at-store (unopened-section-forgery): a reader's blob of a genuine commit with junk in a section a delete-key holder cannot open, planted at a store keeping S unread with a lower blob ID: the store keeps the genuine blob, and a reader opening that section syncing only through the store reads the commit (needs a harness hook placing a hostile node's own entry; the rule is tested at the engine rows and the pure judgement).
- no-server-audit: its 37-row feature table again, with only nodes that sometimes reach each other (no relay, no internet, no node at a fixed address).
- Client port: tracking reads of `role_on`, `holders`, `backlinks`, `profile_of` and `stream` follow a thing at a connected node (tracked-read-port).

## Built, untested end to end
- A record lacking its creation whose delta is not reflected stays unswept (notes/crdt.md, Hidden writes go by a sweep): no world where a record's creation is invalid at a sweep, then a re-grant makes it valid and the entry reads with the edits made into it (osis-crdt `sweep_takes_what_a_parent_reset_hid` and engine `partial_receipt_survives_compaction` cover the unit and the not-yet-received case).
- A dead expiring write is covered before its expiry (notes/ephemeral.md, Ephemeral expiry is durable expiry): B's expiring write overwrites A's on an ephemeral register, a writer's snapshot covers A's then, and every holder forgets it while B's live write stays to its expiry; no engine or world test (`expiry_covers` before T).
- HN_fallany (a snapshot arriving invalid moves the fall mark as one held valid falling does): the engine's `fall_mark`.
- `Live::fresh` (held blobs handed to `Engine::seal_body`): no World test; a mutation passing none fails no osis-sync test (the engine's `rotation::tests_reseal::facade_*` cover the contract). Cheapest found: a purge of one thing's part of a commit spanning two things, the other thing's section then logged again verbatim.

- The facade's waits (notes/sync-facade.md, Pending): one small world per wait and waking event asserting the order property's `lost_wakes` empty, and a world for a refused box freed by room.
- The differential's "a fresh reader that syncs only through a node keeping S unread reads alike" as an oracle clause (notes/sync-test-harness.md): today only the simulation `sims::a_reader_through_a_node_keeping_it_unread_plain`.

## API behaviours the rebuild's deletion left untested
Names from `git show 28641727e`; each goes through the facade.
- libs/chat across synced nodes (libs/chat/tests/it has create, edits, purge sets, cursors on hand-carried commits, a chat minted, joined by link and relayed over sync): deletes and tombstones reaching a new node; a participant kicked while offline: its late post rejected and told, then revived by its re-adding (design E, notes/chat.md Left out).
- Redeem grants (spec/permissions.md §7, spec/sync-inbox.md §6): after a joiner left, a node removal, an expired delivery, a mismatched target, a stalled pull, one refusing peer (old sharing.rs `redeem_*`).
- Cross-node rules other notes list as awaiting sync tests: retention dating (notes/engine-retention-dating.md), destruction (notes/expiry-creation-design.md), paged scale checks (notes/engine-paged.md).

## Simulations still missing
- A rotation of the granter's account thing leaves its grant counted at a node keeping S unread (sync-only-chain).
- Connections and shared-set work counted at 10^2 and 10^3 LAN nodes (every LAN announcer is dialed).
- Both ends of a connection agree on each stream join (a check that would have named refused-join causes at once).
- A refreshed ephemeral value (a cursor rewritten before its expiry) read through a node whose clock is before the old value's expiry.
- The rules old sim seeds reached with no small reproducer (member_churn, work_sets, purge_falls_churn, link_race, parts_relay, large_edits), as scenarios, never pinned.

## Scale
The sync-shaped scale checks the deletion removed: notes/test-scale.md, Checks to restore (engine-level ones go in core/engine/tests/it; the old ones are in git at 680a85188 core/node/tests/it `scale`, `growth`).

## Dead public items
Public items the old sync used that only their own crate's tests call now (osis-store `log_heads`, `table_len`; osis-transport `recheck_relayed`, `relaying`): each is used by a test above or deleted.
