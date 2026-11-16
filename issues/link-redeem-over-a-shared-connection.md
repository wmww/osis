# A link redeemed where the redeemer already shares a connection stays pending
> Summary: Over real sync a redeemer that already shares something with the sharer's node (a third account's card, the harness's `introduce` with three or more nodes) fetches part of K's sync ID and stops: its source for it is gone, K's grant on the target never arrives, and the redeem stays `Pending`. About 31 osis-sync tests fail so in their setup ("0 redeems 2's card"), and osis `sync::importing_a_card_gives_the_account_spec_sync_inbox_5` ("contact card: no holder answered").
> Priority: critical
> Tags: sync, tests

- Repro: osis-sync `links::a_third_redeemer_sharing_another_link_joins_spec_permissions_7`: the fourth redeem (node 0 of node 1's link, the two already sharing K0) ends with K1's sync ID read at node 0 with no source (status `sources: {}` at both ends), node 0's store holding 6 entries of the sharer's 10 under it, and `redeemable` false (the target's roster lacks K1). Cutting the connection before the redeem changes nothing.
- Two nodes redeeming each other's cards works (`harness::contacts`), as does a link redeemed over a fresh connection.
- Likely in opens (a static entry tested on an existing connection, spec/sync-opens.md §4-§5), not in the engine's sync set: K's sync ID is in the redeemer's set throughout.
- `destruction::a_closing_head_takes_a_kept_thing_out_spec_sync_judgement_6` is ignored for it; un-ignore once three-node setups pass.
