# Scale timing checks spend most of their time building their data
> Summary: `scale::late_delta_deaths_cost` at N = 10^4 took 54 min in release under load, 1963 s of it one setup step (filling a compacted keep-at-most set); `scale::sync_pass_cost` and `sync_aspect_pass_cost` 541-765 s, nearly all setup; the measured operation is milliseconds. A timing check should cost its build plus a minute or two.
> Tags: tests, performance, node

Found by the first watchdog review (notes/coordination.md). Fix: build the N-record states in bulk (one commit batch per thousand writes, or a bootstrap from a snapshot/import the test writes once and reuses across cases), keep the measured step as it is, and cache the built store under the scratchpad keyed by N and the data-shape version when a test runs several cases on the same data. Measure before and after with `OSIS_SCALE_N=10000` in release; record the setup/measure split in notes/build.md's table.
