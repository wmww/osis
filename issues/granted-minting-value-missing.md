# A grantee lacks the value of a thing's minting sealed under its mint admin
> Summary: Alice reads T0; Bob's node mints T2 under T0, then grants Alice admin on T2 and Alice strong-holds T2. At quiet Alice holds T2's minting with its `x:v.0` part missing under T0's and T2's sync IDs, which Bob's nodes judge must-hold (the harness's must-hold check fails at the run after the grant). Same on main before and after the closure fixes for lost access.
> Priority: normal
> Tags: engine, sync

## Seen
A test in osis-sync `holding` (siblings world: Alice node 0, Bob nodes 1 and 2), as written:
```
let t0 = make(&mut w, 1, None, "t0");
w.write(1, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
strong(&mut w, 0, None, t0, true);
w.run();
let t2 = make_in(&mut w, 2, t0, "t2");
w.write(2, |e| e.grant(&t2, &alice, &edge(Role::Admin))).unwrap();
strong(&mut w, 0, None, t2, true);
w.run(); // panics: must-hold bodies a caught-up reader lacks at quiet, reader 0, T2's minting, missing parts {0}
```
T2's minting seals T2's value under T0's epochs (T2 not keyed yet), which Alice holds. The grant keys T2. spec/sync-judgement.md §1 Sealed sections: a held blob's sealed section opens again as its thing enters the node closure or a secret of it arrives; here it stays missing. Not traced further.
