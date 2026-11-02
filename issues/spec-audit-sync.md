# Spec audit 2: node sync rules not yet audited
> Summary: Parts of spec/sync.md §3, §6, §7, §9 that audit part 2 did not compare with code (its decisions and gaps are resolved).
> Tags: spec, node-sync, ephemeral

Must-hold "established covered/uncovered" in detail (`must_hold`, `snapshot_carries`); closure tagging and retag; inbox re-send timing; the §9 cap decode bound, ephemeral record lifetime, cover splitting and the caught-up condition before compacting; partial-node repetition.
