# A removed node stays in its account's dial list
> Summary: nothing removes a node's entry from its account's profile `dial^.0` when it is removed from D, so every contact keeps dialing the removed node (each `REDIAL_MS` while it is unreachable) for good.
> Priority: normal
> Tags: sync, engine

- spec/sync-set.md §1 Dial list: "each node keeping its own entry"; no rule takes a removed node's entry out. `Engine::dial_peers` lists every key of a holder account's `dial^.0`, so the removed node stays a `Why::Sync` candidate at every contact sharing a read sync ID with the account.
- Seen in `flows::writers_of_two_accounts_keep_each_others_certificates_spec_sync_judgement_2`: each account removes a paired node and powers it off; the other account's node dials it every `REDIAL_MS` for the rest of the run (about 1 900 failed dials, 1 100 -> 4 600 deliveries, cap raised to 6 x `RULE_CAP`). The candidate went unseen before re-proving after a rotation: it was quiet (closed sharing nothing) and nothing un-quieted it.
- Likely rule: the removal's writer (or any node of P holding a counting removal) deletes the removed node's `dial^.0` entry, keyed by the dialable key of its `reach.0`; spec/sync-set.md §1 states it. A removed node may keep writing its own entry until the profile's roles move; a contact may also ignore entries of keys whose `reach.0` it cannot tie to a current node (it cannot read `reach.0`, so the writer's side is the one that works).
