# A certificate copy outlives the parts it was sealed for
> Summary: an own certificate copy under S carrying parts S's certificates no longer name stays S's log of the commit (it still holds every named part), so what S stores depends on what it once named (spec/commits.md §5: a function of what is held). Seen when an account's holder piece under D carried the thing's chain: the copy of the maker's account-creation commit under D kept the maker D's `keys.0` after the thing went (S1's accept arm, `growth::a_granted_and_revoked_thing_*`); that piece now carries no chain, so nothing default shows it.
> Priority: low
> Tags: sync

- spec/sync-judgement.md §2 counts a copy outside the required set only when it holds none of the named deltas; a copy holding extra ones is never rewritten.
- Likely reachable by any piece whose part set shrinks (a read thing's `Piece::Holder` or `Piece::Chain` as a chain loses an edge write). Wanted: a constructed case, then either rewrite such a copy as a strip is rewritten or say why the residue is bounded.
