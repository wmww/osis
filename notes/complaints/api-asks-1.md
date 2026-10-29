# api-asks-1
- The brief said "do not edit app/" while asking for an API reshape (`groups_of` result type); the gate's GUI `cargo check` then fails on the app's two call sites, so the branch cannot pass the gate as briefed. Briefs that may change the `osis` API should say who adapts the app's call sites in the same branch (here: a two-line `.within` patch, left in the report).
- The scenario helper `private_tag` (core/osis tests) had the very footgun the app hit (tag placed in home but not a subgroup: its items never synced); the new placement check caught it.
- Review gate took 317 s (core tier-1 144 s, sim sweep 75 s, kit/app 48 s): an engine change rebuilds most of the tree, and touching app/ adds the GUI steps on top.
