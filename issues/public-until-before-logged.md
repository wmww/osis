# A public reader's member is ended at a removal not yet logged in S
> Summary: osis-sync opens: a member opened on S's public entry is judged at the public's removal before the removal's entry in S is logged here (the remover's own write; a reader that took the removal under another sync ID first), so `member_until` (`public_edge_at`) finds only the earlier grant and the member closes at once, the removal unserved. The redeemer still learns it by the lapsed read secrets on its next Offer; the open member should carry it.
> Priority: low
> Tags: sync

spec/sync-opens.md §6 (A reader tells a public reader the public's removal): `until` is the highest position at which an entry in S of a commit of the public's edge was first logged. At judge time the engine holds the removal, but its S entry is not logged yet (the remover logs its own commit later in the step; `commit_blobs` may not list it yet either), so `until` names the grant's position, which the peer has passed.

Seen in `differential::a_locators_redeemer_loses_the_thing_with_the_public_*` (trace of node 0 at the Revoke: `until` 99, the removal's S entry logged at 110, a Lost at once).

The fix needs `until` set once the removal's S entry is logged, as Departed does for notices (`departure_until`, `close_if_reached`). Open question: what the member is served meanwhile (everything logged until then is below the eventual `until`, but if the entry never logs here the member is never bounded). The same timing applies to `superseded_at` for a member ended by a read secret when the rotation is judged before it is logged.
