# A node holding none of A's boxes misses a grant's or re-seal's stale box to a holder actor
> Summary: A node holding A's keysets as certificates but none of A's boxes (an admin of G who left A) judges A's epoch stale only by the keyset's `sealed_at` record, which only the rotation writes. A grant or re-seal boxing holder actor M at A's epoch records nothing, so once M moves on (a member removed) that node keeps sealing A at the epoch, which the removed member opens through M's old keyset: past the stated limit (the node holds M's knowing keyset).
> Priority: normal
> Tags: security, keys, engine

Repro: osis `sharing::repro_team_granted_after_left_out_by_a_sealer_reading_none_of_it_spec_crypto_4` (ignored): as `team_left_out_by_a_sealer_reading_none_of_it_reads_again`, M granted on A after Alice left A; Alice keeps A sealed on G after Carol removes Dave from M. The same gap stood under the earlier possession proofs (only rotations' keysets carried them).

Directions: (a) the grant or re-seal records too (a keyset is rotation-written: a separate record A's certificates carry, e.g. the boxes to holder actors projected out of A's `secrets.0` delta, placed with A's keysets under the labels that seal A); (b) a node holding none of A's boxes judges A's epoch by A's holder actors it knows from A's roster: stale where a holder actor's held keyset postdates what the epoch's record names (costs a rotation per honest grant seen this way); (c) a grant of a holder actor rotates A (one rotation per team grant). Model: Depth0.tla has no grant-box path for pf.
