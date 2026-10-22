# Neutrality test flags self-undermining drops on two seeds
> Summary: `joint_resnapshot_neutral_large` fails on `OSIS_PERM_SEED` 6 (sample 3815) and 8 (sample 18665): a drop whose dropped write made its demotion a fall disappears under a re-snapshot. The behavior is an accepted limit (notes/permissions.md, sticky residue; it heals in one sync of the snapshot); the test's detector (`common::sticky_residue`) does not recognize the shape.
> Tags: permissions, tests

Shape: X lowers or removes one of its own paths P1 (write W, unseen by R's author); a later demotion R removes X's other path P2. With W applied R is a fall and drops W; in the restarted walk R is no fall, but W stays dropped. Node-level reproduction: crates/osis-node/tests/validity.rs `resnapshot_residue_heals_on_sync_spec_perm_6`.

Remaining: a detector for the neutrality, differential and projection tests: a drop is residue when its cause R is not applied in the settled walk, or R is not a fall for the dropped write's author there; a snapshot may then only undo such drops.
