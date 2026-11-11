# A reader gets a card stamped for every key actor it mints
> Summary: Promotion takes a key actor's newest own card (`keys.0`, `node.0`, `reach.0`) under any label, because reader nodes' cards must be stamped there (co-readers dial by `reach.0`) and a group label's writer cannot tie a node to its account. Anyone with the deposit key can mint key actors at no cost and write each a card with chosen bytes (`reach.0` items): each is stamped and kept. Bounded by the deposit rate and label caps only.
> Priority: normal
> Tags: security, sync, tess-call

Probe: `promotion::a_readers_minted_key_actors_cards_are_not_promoted_spec_sync_5` (ignored; 20 of 20 stamped, 4 KB each).

Why not "cards only of authors of commits the label must hold": a node authors nothing but its own card (its account authors the rest), so a pure reader node's card would never be stamped. It would sit deposited, count toward the clearing cap (32 per host), and be cleared and re-deposited past it; co-readers find nodes by it (`pending_bound::reader_flood_of_pending_stays_within_the_cap_spec_sync_3`, `sync_more::certificates_spec_permissions_4`, `local_serve::deposit_promoted_on_local_label_spec_sync_5`, `inbox_life::readers_burst_under_a_group_inbox_stays_spec_sync_5`, `wrap_poison::useless_*` all fail under that rule).

Directions: issues/account-signing.md step 7 (no node card under group labels; dialing by another path) removes the class. Short of it, the label would need a writer-checkable node-to-account link (the account's devices actor edge naming the node, as a chain certificate) and a bound on nodes per account, which an account can grow at will too.
