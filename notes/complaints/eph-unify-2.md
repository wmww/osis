# eph-unify-2
- Wall-time measurements swung 3-5x within minutes (load 7 to 67 from other agents); only `tools/icount` deltas (N=2000 vs 4000) were stable. A bench that prints spans per phase helped more than any total.
- First bench wrote the test schema's `/t/count` (`counter<int>`): its join grows with every write, so per-write cost grew 7x from 2000 to 4000 writes in durable and memory modes alike, which looked like an overlay bug for a while. Benches of write cost should use a plain register.
- Each release rebuild of osis-node `it` after an engine edit took about 3 min under load; probing phase costs by adding temporary spans cost three of them.
- Review: the gate took 383 s (tier 1 207 s) at load; `tools/bin-at main` to confirm a pre-existing oracle failure cost about 2 min of rebuild each way.
