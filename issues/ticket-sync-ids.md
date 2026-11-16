# A ticket's sync ID is never synced
> Summary: A node entering a thing by a ticket alone (no record or `sync.0` of it held) syncs no sync ID for it: `thing_sync_now` reads `sync.0` only, so the thing reads `Plain` and nothing arrives over real sync. Accepting a stranger's grant works only where the harness delivers everything (`LocalPeer::sync_all`). The ticket's sync ID (its issuer's word, spec/sync-inbox.md §5 Ticket sync IDs) and the Tied rule (spec/sync.md §3) are not built.
> Priority: critical
> Tags: sync, engine, security

## What happens
- Alice grants Bob read on T; her ticket reaches Bob's inbox as a sealed fire; Bob writes a strong to T. The walk enters T (`closure_holds`), and Bob holds the read secret, but `Engine::thing_sync(T)` is `Plain`: `owned_sync_ids` needs T's `sync.0`, which Bob can get only through T's sync ID. Repro: a two-account test as `sync::tests_tickets` builds, asserting `sync_set().ids` holds the ticket's `sync_id` after the accept.
- `Ticket::sync_id` is read only by `ticket_sync_secrets` (kept unread, filtered against a sync ID owned by a held `sync.0`): never to put a sync ID in the sync set.

## To build (spec/sync-inbox.md §5 Ticket sync IDs)
- A thing entered by a ticket whose `sync.0` is not held syncs the ticket's sync ID: read until a held `sync.0` records it, kept unread until a step of it bears the ticket's sync key (Tied). Several tickets naming one sync ID under different things: tried in turn, each retried after `resync_ms`.
- Forged sync IDs (refgraph-tests T5): a ticket naming another thing's sync ID, a stale epoch, or a target the issuer does not hold must open nothing and cost one try per `resync_ms`. Test each.
- Likely the same cause: the osis-sync harness's world setup redeems every node's card over real sync, which stays `Pending` (`history.rs`: "redeems 1's card"; 56 osis-sync tests and osis `sync::importing_a_card_gives_the_account_spec_sync_inbox_5` fail so). `destruction::a_closing_head_takes_a_kept_thing_out_spec_sync_judgement_6` is ignored for it: un-ignore it once the setup passes.
