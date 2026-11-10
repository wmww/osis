# A grant then at once a demotion rotates the granted thing's secrets seven more times
> Summary: `Net::grant(a, t, c, Admin)` followed before any pass by a demotion of c on t's group g (no rotation) makes t's holders write `keys.0 secrets.0` on t seven more times (a and c, its two admins, three each; the writer b once), plus `secrets.0`-only writes by all three, where a pass between grant and demotion gives one rotation; each commit travels and wakes every node's pass, so the run takes 37-54 passes per node against 12-19.
> Priority: low
> Tags: engine

Seen in osis-node `deletion::reregistration_waits_and_sends_once_spec_sync_5` (and `ending::a_grant_holder_ends_and_a_stale_copy_ends_again_spec_permissions_6`), with `OSIS_TRACE_UPLOADS=1`. After the grant (a's commits writing t's `keys.0 label.0 secrets.0` and `roles.0 secrets.0`) and a's rotation of g for the demotion, the role commits on t are: by a, three `keys.0 secrets.0` rotations, two `secrets.0`-only writes and a `label.0` step record; by c, three `keys.0 secrets.0` rotations, a `secrets.0`-only write and a `label.0`; by the writer b, one `keys.0 secrets.0` and one `secrets.0`-only write. With a `net.run()` between the grant and the demotion: one rotation of t by a, and one `label.0` each. The same commits appear whatever node sync does with them (identical before and after the re-registration upload fix), so the cause is in the engine's `rotation_due` (likely a stale box of t to holder actor g after g rotates, both admins of t rotating it, then fork merges), not in sync.

Totals over grant + demotion + `net.run()`: 23 uploads, 5 deposits, no deletes; passes per node (both labels) a 37, b 44, c 54. With a run between: 11 uploads, 12 / 19 / 19 passes.

Next: trace which `rotation_due` rule fires for each of t's rotations (blocked, merge_due, fork_merger, keyless_at, stale_at) and check whether each follows from spec/crypto.md §4 or is the same departure answered twice.
