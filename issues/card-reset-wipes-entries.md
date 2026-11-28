# Any writer of a card's host can wipe every node's entry
> Summary: spec/permissions.md §5.2 lets any writer of the host reset `:<A>:card.0`, and a whole replace naming only the signer's own entry passes `validity::own_entries` (it checks the entries written, not the root reset), so one valid write leaves only the writer's entry; until honest nodes rewrite theirs at a pass end, a party taking the card takes the writer's holder keys alone (a lowered admin still writing through A can point strangers at its inbox, repeatedly).
> Priority: normal
> Tags: security, engine, spec

Confirmed by a probe in the engine's `cards` suite (the setup of `a_card_entry_counts_only_written_by_its_node_spec_permissions_5_2`): node 1, a writer of A0 but not node 0, writes the whole card holding only its own entry, and `cards::put` (the empty card); both are valid at node 0, and node 0's entry comes back only by its own rewrite.

Options: (a) a card delta that is not a compaction snapshot writes or removes only its signer's entry, never a root reset (`cards::put` goes: a card exists once its first entry is written); who may then remove a gone node's entry or the whole card (the node's account's admins? its entry's expiry?) is the open part. (b) Keep resets, and readers take a card only once a pass has rewritten their known entries (weaker: a window remains). Test: a whole replace naming the signer's own entry is invalid.
