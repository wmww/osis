# Re-snapshot neutrality fails when a drop removes its own cause
> Summary: `joint_resnapshot_neutral_large` fails on `OSIS_PERM_SEED` 6 (sample 3815) and 8 (sample 18665), also before the certificate fix: the full walk keeps a drop whose dropped write was what made the demotion a fall; the re-snapshot's roster (computed with that write dropped) replays the demotion as no fall, so the drop disappears.
> Tags: permissions, tests

Seed 6 sample 3815 (seed 8 not yet looked at; likely the same). Nodes n0, n1; A0 owned by n1, A1 by n0, A2 by A0. Genesis: A1 admin on A0, A2 write on A1. n0 at t1 makes A2 admin on A0; n0 at t2 removes it (w0, n1 never receives it); n0 at t5 gives n1 write on A2 (w2); n0 at t6 makes A1 admin on A2; n1 at t8 lowers A1 to write on A0 (w6).

Full walk: at w6, n0 has no other admin path to A0 (w0 applied), so its class falls; w0 and w2 are dropped and the walk restarts. In the restarted walk A2 stays admin on A0, so n0 keeps admin through A1 -> A2 -> A0 and w6 is no fall, but D only grows (§5.1 step 4), so w0 and w2 stay dropped. A re-snapshot of A0 by n1 carries A2 admin since t1 and A1's tenure ended by w6 with its frontier; the replayed demotion is no fall and w2 stands.

Like sticky residue (`common::sticky_residue`, models/tla/membership M2) but the cause is not itself dropped, so the test does not skip it. Options: widen the residue detector to "a drop whose demotion is no fall in the settled walk" (and accept the snapshot repairing it, as for sticky residue), or change the walk. Decide with the M2 owner call.
