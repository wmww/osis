# certificates_project_joint_large fails at OSIS_PERM_SEED=115000
> Summary: osis-perm's certificate projection disagrees with the full evaluation (full: applied; certificates: dropped) on a 3-node joint history found at OSIS_PERM_SEED=115000; pre-existing (seen reviewing rotate-carried, which does not touch osis-perm).
> Tags: perm, security

Repro: `OSIS_PERM_SEED=115000 cargo test --workspace --test it -- --ignored queries::certificates_project_joint_large` (shard seed 0x6005eecc33a, sample 981). Write w0 (`ae202bfc`) is applied by the full timeline but dropped by its certificates:

```
nodes n0..n2; A0 owned by n2, A1 owned by A0, A2 owned by n2
  genesis: n0 Admin on A1; n1 Admin on A0; n1 Admin on A1; n2 Write on A2
  genesis: A0 Admin on A2; A2 Admin on A0; A2 Admin on A1
  w0: t=2 n0 sets n0 on A1 := Write | recv n1 -, n2@1
  w2: t=4 n1 sets n0 on A0 := Admin | recv n0@2, n2 -
  w1: t=6 n1 sets n0 on A1 := None | recv n0 -, n2 -
  w3: t=7 n2 sets n1 on A0 := None | recv n0 -, n1 -
```

A cycle (A0 and A2 admins of each other) and n0's self-demotion on A1 then regained admin through A0: likely the "demotion on a later path" rule (notes/permissions.md, Implementation (osis-perm), Certificates). Pin it as a `_spec_permissions_4` test before fixing.
