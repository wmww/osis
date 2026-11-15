# Pairing as a rotation breaks three osis-sync tests
> Summary: With custody's pairing rotation (and joiner-target on main), three osis-sync tests that pass on main fail on fathom-custody-engine: a new device keeping a sync ID unread never gets its head, a two-account certificate test storms, and a contact keeps dialing a removed node through a re-seal's inbox hint.
> Priority: normal
> Tags: engine, sync, tests

- `siblings::a_sibling_paired_after_inbox_lifetime_keeps_an_accepted_grant_*`: the paired node keeps S (t's sync ID) unread from the record but holds no head of S, so it refuses every pulled entry (`Store` log: no `path::head`). Not yet found why the pairing rotation stops it learning the path (likely: it proves the account at the pairing's new epoch, which the granter does not hold yet).
- `flows::writers_of_two_accounts_keep_each_others_certificates_*`: storm past the 2000-delivery cap after a pairing.
- `driver::a_removed_node_is_dialed_no_more_by_a_contact_*`: the contact's only reason to dial the removed node is an inbox dial hint (`Why::Hint`): right after pairing, the new node's first pass end re-seals the account's things to every holder (`reseal_candidates` finds them all lacking a box), and the re-seal's inbox blob carries its hint until it expires. Find why a fresh node sees every holder unboxed.
- Already fixed on the branch: every pairing made every box to P stale and re-keyed every thing P holds (stale is now: at a revoked or uncounted epoch only, spec/crypto.md §4 Account keysets). That turned the siblings storm into the head failure above.
