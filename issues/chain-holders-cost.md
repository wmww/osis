# A grant re-walks every chain of its unit
> Summary: Each grant settles the sync units (`sync::units::settle`), whose `chain_holders` walks, for every holder with a role on a thing, the counted roles both ways, each walk scanning every roster on the way: about holders² × roster per thing judged, at every grant. 61% of engine lib `rotation::tests_members::diamond_and_lattice_rotate_once_spec_crypto_4` (55 G, 132 grants over a 37-actor lattice).
> Priority: normal
> Tags: engine, performance, tests

`Engine::grant_with` ends its flows with `sync::units::given_by` -> `settle` -> `judge`, which asks `chain_holders(core, c, o, a, r)` per unit `c` and independent `a` it judges. For each holder `h` of a role on `a`, `chain_holders` asks `role_counted(o, h)` and `role_counted(h, a)`; each `role_counted` reads `roles_now` of its target and, for that target and every thing with a role on it, every roster entry through `counted` (in the local part `local_log::counts`, 36% of the test alone). Nothing is kept between holders, units or grants.

Measured (cpuprof, `CPUPROF_INSTR`, engine lib at 2114d59ad): the lattice test 55 G (21 G before the sync-only chain cuts); 69% under `grant_with`, 61% under `units::settle`, 55% under `chain_holders`. Not yet counted at n and 10n: count `role_counted` calls per grant on a lattice 4 wide at depths 3 and 10 (spec/requirements.md Scale: a grant costs what it changed).

Directions: the skip set of (target, holder) pairs a unit's judgement does not count, built once per settle and shared by every holder and `a`; or one reachability pass from `o` over the counted grants per (unit, role) instead of a role evaluation per holder pair.
