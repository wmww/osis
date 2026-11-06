# Recovery, from scratch
> Summary: Recovery (the recovery key, `RecoveryCard`, `restore`, CLI `restore`) was removed from the API until a design is agreed (Tess). Not urgent. Needs Tess's input.
> Tags: api, permissions, tess-call

Removed because it was tied to saved peers (no card without them, the key discarded, issues/node-host-unify.md) and Tess wants it rethought whole. notes/owners.md records her direction: no recovery key by default, and a stolen unlocked device accepted. notes/owner-removal-plan.md makes a recovery card an ordinary key holding an admin role.

Until then an account is reached again only through one of its other nodes.

What stays inside: the engine still mints a key for the account's creation record while owners exist, and drops it (`create_person`); the engine's `recover` and its node tests (core/node/tests/it/flows.rs: `stolen_device_recovery_spec_perm_7`, `recovery_erases_whatever_the_default_spec_perm_2`, ...) and `osis_label::RecoveryCard` stay until owner removal. Spec text on recovery cards (spec/permissions.md §7, spec/wire.md §10) is marked as not built.

## Removed
- API: `RecoveryCard`, `Osis::restore`, `internals::restore`; `Osis::create` returns just the `Osis`. CLI: `restore`, and `init` no longer prints a card. Sim: `World::account` returns just the node. No app UI had it.
- Tests deleted: `sync::restore_from_card_spec_permissions_7`, `sync::restore_fails_when_the_head_moves_under_it_and_a_fresh_attempt_works` (and issues/restore-head-moved.md, below), `sharing::links_around_a_recovery_spec_permissions_7` (links made before and after a recovery; the paired-node case is `links_listed_on_every_node_and_one_paired_later_spec_permissions_7`); the restore half of `sharing::waits_time_out_and_roll_back_spec_api_handle` (a dropped restore leaves no account record) and of chat's `creator_on_a_new_device_spec_sync_3`.
- Tests moved to pairing for their second node: `serving::serving_own_then_open_spec_sync_5`, `runtime::round_trip` (its callers), `sync::restored_store_writes_at_once_spec_crdt_2_1`, `sharing::links_listed_on_every_node_and_one_paired_later_spec_permissions_7`; cli `@FILE` reading checks `link redeem`.

## From issues/restore-head-moved.md (deleted with the test)
A head that moved while a fresh node read the home group by the card's key stranded that restore for good (5 of 32 sweep points with one saved peer, 6 of 60 with two): the label went `Stranded` with nobody to re-seal to (the node was on no roster yet). Admitting the card's key in `rest_tries` (`Some(t) == via`) did not help alone; a fresh attempt worked. A redesign that claims a label by a static entry meets the same race. Also: `SyncState::Stranded` is any one saved peer's `Phase::Failed`, so one peer that no key opens keeps a group from `Synced` while another serves it.

## Questions for the design
- Is recovery an explicit act after `create`, any time, with or without peers?
- Where the data comes from on restore: any node of the account, saved peers, or an address typed in.
- How a lost or stolen card is revoked.
- Interaction with disputes (owner removal step 3).
