# Tests failing since opening by entries landed
> Summary: 6 osis-sync tests still fail since the entries design: public grants on a holder or a re-granted public not read, a signal a removed node took and relayed, a grant from outside an account that removed a node, and a stub fetching a record blob again once raised to read.
> Priority: critical
> Tags: sync, engine, tests

Each is in tools/known_failures.txt against this issue.
- `differential::the_public_granted_again_is_read_again_*` (no quiet run between the public's removal and its re-grant): node 0 reads thing 1 (made in thing 0, made independent by a grant to node 0) and through it thing 0 by the public; after the public's revoke and re-grant on thing 0 it sees the public's read and the admin on thing 0 but reads no value of it. Not traced past that.
- `differential::the_publics_read_through_a_holder_is_every_nodes_*`: node 1 reads nothing of thing 0 (role none). Not traced.
- `keep::a_grant_from_outside_reaches_an_account_that_removed_a_node`: node 1 reads nothing of the thing granted to its account after the account rotated for a removal. Not traced (suspect: the grant's entry sealed to the account's KEM key node 0 holds from before the rotation, and node 1 not trying that keyset's claim).
- `differential::a_signal_only_a_removed_node_took_is_lost_*` (removed case): node 0 holds thing 0 as a stub with the entry's sync secret. Likely node 0 pulled the fire from node 3 before node 3 learned its removal (a valid fire, relayed), so the engine holds a signal the model says no node of the account holds: an oracle question (does a removed node's relay of a fire it took count as delivery?).
- `first::a_blob_is_fetched_once_*`, `first::what_a_reader_fetches_and_drops_does_not_grow_*`: a grantee follows its signal as a stub first, fetches the maker's losing record blob, drops it as a stub needs it not, then raised to read pulls S anew and fetches it again. Options: keep what a stub fetched until judged as a reader after the raise; or the tests count fetches per holding.
