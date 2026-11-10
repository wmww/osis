# A link redeemed while a grant waits as an invite request strands on the target
> Summary: With raw records (notes/expiry-creation-design.md step 8), `osis` `sync::redeem_held_joins_nothing_spec_none` fails: Dave, granted on g by a stranger and so holding the grant as an invite request, redeems a lasting write link to g and is stranded on g's label ("walked step does not verify under its parent"); on main the same redeem joins.
> Priority: critical
> Tags: node-sync, tests

Found on branch `expiry-8` (unmerged); the branch must not merge red.

What is known:
- Nothing ends in the test; the ending code is not involved.
- Alice's inbox grant to Dave reaches Dave's inbox and is held as a request (Alice is a stranger to Dave: she read his contact card by bearer use and wrote nothing he holds), the same as on main.
- During `dave.redeem(&lasting)` Dave holds three read epochs of g but his opens of g's label are refused (code 1), then the walk diagnostic above, then `Stranded`.
- Ruled out by experiment: re-queueing awoken entries in a fill, keeping the account's creation copy in the cards beside its raw record, leaving the node's record out of certificates.
- Not yet looked at: which records Dave learns from record blobs on the links' labels (`cdc6…`, the first link's) before the redeem, and whether one of them makes him try a claim or static entry of an actor whose record he now knows (a key actor known only by its raw record).
