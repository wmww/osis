# A left-out record outlives the invalidated cause that made it
> Summary: a writer of G leaves holder actor M out of G on a stale box whose staleness comes from a rotation (of N, below M) that later turns invalid; G's keyset records M's current keyset, nothing is blocked once all is held, so no rotator of M ever re-keys and M stays out of G for good. Design question in Left out (spec/crypto.md §4). Reproducer `rotation::tests_members::repro_left_out_on_an_invalidated_rotation_spec_crypto_4`.
> Priority: normal
> Tags: engine, security

Property violated: every holder of G with key access ends boxed at G's current epochs (spec/permissions.md §3; the rotation property's "a holder ... lacks a box"). A permanent lockout of an honest holder actor with no hostile party: invalid data (the invalidated rotation) keeps an effect on G forever.

## Cause (probed on `rotation_holds_large` seed 96284297771, rebuilt by hand)
G {g0, W admin, M}, M {m0, N}, N {n0, P admin}.
1. P rotates N (keyset k1' listing k1); n0 demotes P concurrently, so P's rotation is invalid once both are held.
2. W holds P's rotation, not the demotion. M's epoch boxes N at k1, listed by k1': stale at W (`members::stale_at`, `Block::Box`). W rotates G and Seal leaves M out; G's keyset records M left out at M's current keyset.
3. Everything syncs: P's rotation is invalid, k1 is N's only keyset, M's epoch is not stale anywhere, no departure from M exists. M's rotators have nothing due, and `left_out_for_good` skips a recorded keyset that is current at the node (it waits for "the knowing re-key"). Every later rotation of G records M again (spec: no rotation of A drops a record). M is never boxed.
The same holds for any cause that later turns invalid: a departure from M by an admin demoted concurrently, a side switch in an admin dispute.

Not account machinery: holder actors, staleness and left-out records only.

## Why no patch
The spec and notes/holder-actors.md (Left out) deliberately make a record at a current keyset wait for M's knowing re-key: a rotator of M that judges the keyset unblocked cannot tell "the cause is void" from "I have not received the departure yet", and rotating in the second case makes an ignorant keyset past the record that sealers of G seal to (a leak until the knowing re-key). Dropping the record on a node judging it unblocked is already rejected there for the same reason. So the record's effect needs to depend on its cause, which no record carries.

## Candidate fix (design change)
Carry the cause: a rotation of A carries (spec/crypto.md §4 Carried), beside the recorded keyset's rotation commit, the commits that blocked it at the recorder (the uncovered departures' edge writes; the rotation commit of the keyset that made a box stale; an invalid keyset's body; a taint's grant), at whatever depth the blocking walk found them. A node that may rotate r of M, holding the record, its carried commits, and the recorded keyset current and unblocked, then knows the cause is void and rotates M as Left out for good does. Needs: `blocking` to return its causes, records or carried commits extended (wire), spec Left out / Carried, Depth0.tla checked against it. Alternative to weigh: accept the early (ignorant) rotation's leak window and drop the "none current" clause, which notes/holder-actors.md rejected.
