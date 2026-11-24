# held-model refuses edge writes on a thing whose record holds a key
> Summary: held-model's roles reading applies no edge write on a thing whose record holds a key (the old "no edge write targets a key actor" rule); spec/permissions.md §1 and osis-perm's walk (with roles-model `paths`) take them as on any thing, the key hop an edge. Goes with the models piece of accounts as ordinary things.
> Priority: normal
> Tags: tests

held-model `roles.rs` (the walk's input from a held world) refuses every edge write on a key-record thing (`tl.world.key_actor(thing)`, marked Interim). The walk and roles-model `paths` read a thing's roster and key grants written by itself, by its key hop, as any admin's (notes/write-path-design.md, Keys K1 to K5). Replaced by: held-model generating and reading them alike (notes/accounts-switch-brief.md, piece 7).
