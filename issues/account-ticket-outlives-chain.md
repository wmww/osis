# The account's ticket keeps a chain reader reading
> Summary: A node reading T only through a chain of actor grants writes D's ticket for T; its holder (the account) is never named on T, so by spec/sync-set.md §2 What a held ticket does its word (read) counts for good, and the lost-access trigger never fires when the chain is cut.
> Priority: normal
> Tags: sync, security, tess-call

- Case (osis-sync `holding::a_removal_reaches_a_reader_opening_the_holder_through_a_second_thing_spec_permissions_4`): Bob reads T1, T1 holds read on H, H on X, T1 -> X. Alice removes H from X. The removal reaches Bob (his role commits show no role on X), yet `tickets::role_on(X)` stays read: the D ticket his node wrote when the walk entered X (spec/sync-set.md §1 The account's tickets) names Bob's account, which no role commit on X names. `lost_due(X)` is false, so Bob keeps X's secrets, its old content and its sync ID; he opens nothing sealed after the removal's rotation.
- The rule's reason ("a node keeping T unread holds only the role commits other things' certificates bring, which cannot show its own grant") holds for a direct grant only; a reader by chain holds T's roster and is never named there.
- Call: what bounds a ticket's word for a node that holds T's role commits. Candidates: the word of the account's own ticket (sealed to P by its node) never counts, since D's ticket only records what the walk entered by role; or a word counts only while no held role commit of T reaches the holder by any path (named or by chain).
- Expected after the fix: append to the test above `w.advance(PASS_WAIT_MS + 1); w.run();` and assert Bob reads X no more.
