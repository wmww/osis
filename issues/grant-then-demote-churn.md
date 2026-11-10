# A grant and a bare demotion in one step churn uploads
> Summary: In osis-node `ending::a_grant_holder_ends_and_a_stale_copy_ends_again_spec_permissions_6`, `Net::grant(a, t, c, Admin)` (t plain, first admin g) followed before any pass by the hand-built demotion of c on g (no rotation) settles after about 63 uploads, 17 deletes and 45 passes per node; with a `net.run()` between them, 7 uploads and 13 passes; with a bare edge write instead of the grant, 6 uploads and 8 passes. It settles, so no loop, but uploads and deletes of the same few bodies look repeated. Not traced.
> Priority: low
> Tags: node, sync

Repro: add `println!("{:?}", net.sent_kinds)` (10 = upload, 14 = delete) and `pass_stats().passes` per node after the `net.run()` that follows `demote(...)` in that test.
