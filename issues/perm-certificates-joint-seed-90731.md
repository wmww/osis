# perm tier 2 `queries::certificates_project_joint_large` fails at OSIS_PERM_SEED=90731
> Summary: the certificate-projection differential finds a write the full timeline drops but the certificates-only timeline applies (shard seed 0xf005eec6069, sample 685); osis-perm only, found on a reviewer's fresh seed, not caused by the branch under review.
> Tags: perm, tests

Repro: `OSIS_PERM_SEED=90731 cargo test --workspace --test it -- --ignored queries::certificates_project_joint_large`.

`write Op(CommitId(69ffec9e..), 0): full applied false dropped true Standing { class: Edge, role: Some(Admin) }, certificates applied true dropped false` (same standing). History: nodes n0..n2; A0 owned by n0, A1 and A2 by n1; genesis n0 Write on A0, n2 Admin on A0, n2 Write on A1, n2 Admin on A2, A1 Admin on A2; then w5 t=2 n1 sets n0 on A2 := Admin; w4 t=2 n2 sets A2 on A0 := Write; w6 t=4 n0 sets n2 on A2 := Admin; w3 t=4 n2 sets n0 on A2 := None; w1 t=5 n1 sets n0 on A1 := Admin; w2 t=7 n1 sets A1 on A2 := None; w0 t=8 n2 sets A0 on A2 := None (recv vectors in the panic). Decide whether the model or the projection is wrong (spec/permissions.md §4, §5.1).
