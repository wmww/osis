# A public key record's newer `keys.0` copies arrive without the steps placing their keys
> Summary: after an account's inbox rotates (removing a node does), a contact holds the inbox's newer `keys.0` as certificate copies without the inbox's `sync.0` steps, judges them miskeyed, seals grant fires with the old deposit seed, and the account's nodes refuse them (14): grants from outside stop reaching the account.
> Priority: normal
> Tags: engine, accounts

Repro: osis-sync `keep::repro_a_grant_from_outside_reaches_an_account_that_removed_a_node` (siblings: node 1 removes node 2, node 0 grants node 1's account read, node 1 never reads). Found by the sync differential (its `Unpair` seeds; known_failures `rate:` line).

What happens: `remove_node` rotates A and the inbox (the removed node read both). Node 0 (a contact, reading the profile) takes A's public key record from the profile's sync ID (`Engine::public_key_record_into`: records and the latest `keys.0` of A and its inbox) as copies of the `keys.0` parts alone. The inbox's rotations list delete keys placed by steps whose `sync.0` writes node 0 never holds (its copy of the inbox's minting has `sync.0` missing; first steps cover the minting only), so it judges them miskeyed (shown invalid by `describe_commit`). Its current `keys.0` of the inbox stays the minting's, so `fire_keys`/the deposit signature use the old deposit seed; node 1's store verifies Deposit items under its new head and answers 14 (`Store::take_deposit`). spec/sync-inbox.md §3 has the sender sign again "with the current deposit key", which it does not hold.

The spec's answer: the steps placing a listed key ride with the commit as its evidence (spec/crypto.md §7 Checked keys, spec/permissions.md §4 Evidence of a commit: every `sync.0` write recording a step on the path to the key). The public key record's copies carry no such `sync.0` writes. Belongs to the evidence derivation (the certificates-follow rework).

Done when the repro passes unignored (renamed without `repro_`) and the sync differential at full size passes its `Unpair` seeds.
