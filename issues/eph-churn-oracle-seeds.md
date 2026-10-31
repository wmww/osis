# random_churn oracle: three seeds diverge after a demotion, server restarts and a re-promotion
> Summary: `ephemeral::random_churn_converges_large` fails seeds 154 and 169 of 0..300, 118077 and 119026, whether or not superseded expiring writes are dropped: a demoted-then-promoted author's ephemeral commits come back only at holders that kept them waiting apart; no cover is involved. Traced in review of eph-restart-seeds.
> Tags: ephemeral, node-sync, tests

Replay: `OSIS_EPH_START=<seed> OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large --nocapture`. The failure prints each never-demoted holder's reads, the commits held only at one of them and the step log.

Trace (temporary eprintlns in `release_held`, the pending promotion in `eph_step` and `reconciled`; same in all three seeds):
1. The author is demoted (`PreSync::Synced`: the revoke's frontier names durable commits only, so its earlier ephemeral commits turn invalid). Every holder's `rejudge_ephemeral` releases them (all parts invalid); `eph_unhold` forgets the lane entries and clears `reconciled`.
2. Holders that reconcile afterwards fetch them back; they wait apart (`eph.pending`, `EphIngest::Pending`): neither served nor uploaded. A holder that is offline or blocked meanwhile (154: node 0, offline from the step after the demotion; 169, 118077: node 3) does not.
3. Both servers restart and lose them. Nobody re-uploads: no holder holds them valid.
4. The author is promoted again: the commits are valid again (judged at their stamp). The waiting holders promote them (`eph_step`, `eph_added_with(RelayFrom::Server(from), ..)` with the server recorded when they began to wait), which marks them present at that server although it lost them. So they are not uploaded there, and they are not relayed to the other server either: their stamp is under a write key from before the rotation. The author holds them as an earlier session's commits (`own` false), so it does not upload them either.
5. The holder from step 2 that forgot them reconciles after the heal; neither server lists them, so it never gets them back. Seed 154: node 2 holds `da1b97` (node 1's step-2 write `fhWp=v2`, expiring at 40 min) and reads it, node 0 does not.

Two defects (the second alone would let them reach the server not marked present; the first alone uploads nothing while the stamp is stale):
- A pending entry's promotion trusts presence recorded when it began to wait; a server restart since then (no `eph_lost` for an entry that only waited) leaves it stale. It should count as present nowhere, or be checked by the next reconcile.
- A held entry whose stamp no longer verifies under the head's write key cannot be relayed by anyone but its author, and the author treats an earlier session's commit as someone else's. A holder with write access could stamp it again under the current key, as an author does with its own entries (spec/sync.md §6, code 9).

The oracle skips nodes once demoted, whose view of their own writes differs. Fixed earlier: 203 (eph-restart-seeds: own expiring writes made while the thing was in no labeled closure were never sent).

119026 (review run 119000..119200): the same; node 2's commits `1cc973`, `bc8c67` released at nodes 0, 1, 3 at its demotion, promoted back at node 1 only (from the server it waited on, after both servers restarted).

Each seed found later goes here with its class; the oracle is a periodic check until this list is empty.
