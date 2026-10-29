# dropped-voucher
- The order oracles never call `Engine::drop_body` (node-sync's compaction drop), so anything keyed on compaction drops is invisible to them; the walks now do (half their snapshots drop what they cover). The first oracle run "passed" a version that un-dropped keep-at-most drops too; only the walks' open-equals-rebuild caught the resulting index drift.
- `Meta::dropped` and `Meta::missing` are both derived at load (missing = neither in the blob nor dropped), but nothing enforced it live: a part could be both. Worth a debug assertion in `put_commit`.
- Sim: an OR-set add of a value the set already holds can commit nothing, and two snapshots with equal content are covered-equal (the higher ID drops itself); a scenario needing a strict cover must write a fresh value first.
