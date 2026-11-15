# A sibling taking a removal's rotation before its D list leaves its account
> Summary: at a node of P, a rotation carrying a removal from D (header field 15) decides on D at once (spec/permissions.md §5.5 Waiting), so a sibling not removed that holds it before its thing list for D (from a Prove's rotations, or a header-only copy under another sync ID) reads D's roster as P alone and leaves for good (`signing::leave`). Fix: custody's rule (e).
> Priority: critical
> Tags: engine, sync

- Fix (Fathom's custody build, notes/account-forks-design.md Custody): rule (e), a node leaves only on a rotation counting on the chain it follows, superseding an epoch it held, with no box to its device key. Then the removal clause of Waiting goes: Waiting holds for every closer, and a removed node learns its removal from the rotation that boxes it nothing.
- Why the clause stands until then: a removed node gets neither its removal nor D's later lists from its siblings (they serve D only to D's roster), so reading D's roster as P alone is how it learns it was removed (osis-sync `duties::a_node_removed_from_its_account_stops_syncing_*`). A sibling and the removed node hold the same thing at that moment; only what arrives later tells them apart, and `leave` drops the account's seeds at once with no sibling left as a peer to wait for.
- The clause reads field 15 unjudged. That adds nothing for a hostile signer: any closer that counts and whose D list it wrote decides alike.
- Shape to test: siblings 1, 2, 3; node 1 removes node 3; node 2 takes the rotation from node 1's Prove before home brings the removal and the list.
