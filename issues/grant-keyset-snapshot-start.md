# A roster snapshot drops a grant's keyset binding
> Summary: A boxer holding a grant of holder actor N on A without its `secrets.0` part is bound to the keyset the grant's edge names only while that edge write is applied; once a roster snapshot of A is A's epoch start, earlier edge writes are ignored, the snapshot names no keyset, and the boxer seals N at its own newest keyset (study C3 reopened).
> Tags: security, keys, engine

Repro: `rotation::tests::repro_grant_keyset_snapshot_start_spec_crypto_4` (osis-engine, ignored): `grant_projection_names_unheld_spec_crypto_4` with G writing a roster snapshot of A after the grant; X boxes N at D's forged keyset.

Why only the projection path: a boxer holding the grant's boxes meets their names through the current-epoch boxes, and a later rotation of A carries the knowledge in its history-box names. A boxer lacking the boxes has only the edge write, which the snapshot start hides (spec/permissions.md §6 "edge writes ordered before S are ignored"); `departures::grant_names_held` reads `edge_writes` (applied ops only).

Directions (not judged):
- Bind on every held valid edge write of N on A, applied or before the start (ix.holder_keys dots, the commit's `roles.0` part valid); lost when those parts drop after `ROLE_KEEP`.
- The snapshot carries the standing edge's `keyset`; a snapshot entry with a keyset binds a boxer that holds no names-carrying box to N at a current epoch of A (liveness: binds after later rotations too).
- `roster_snapshot` rotates A first when a current box to a holder actor carries grant names, so the knowledge travels in the rotation's history names; check that a boxer not establishing that rotation cannot box N at all.
