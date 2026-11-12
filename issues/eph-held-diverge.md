# Memory commits held differ between nodes after a demotion
> Summary: In `ephemeral::memory_random_snapshots_demotion_redelivered_alike_spec_permissions_5_2`, reads agree over 400 seeds, but at about 1 seed in 100 (67, 127, 139, 217, 391, 395) one node keeps a demoted author's memory commit the others dropped, after every blob was delivered everywhere. Which commits a node holds then depends on arrival order: memory kept until restart, and a sign that some rule is not a function of the commits received.
> Priority: normal
> Tags: ephemeral, engine, tests

- Reproduce: raise the test's seed loop to `0..400`; the held-alike assert fails (main and eph-unify-close alike, both demotion modes).
- Seed 127 (odd seed: the admin's own demotion): the demoted node 1 writes a snapshot after the demotion's stamp, before the demotion reaches it. Node 3 receives the snapshot while it is still valid there and keeps it after it turns invalid (invalid memory parts stay held). Nodes 0 and 2 receive it already invalid and end up without it.
- Find the rule whose outcome depends on that order (covering an invalid snapshot, the drop of a part invalid on arrival, superseding), make it a function of the commits held, then add a small test for it.
