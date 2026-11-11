# snapshot_rights: a purge-on-replace body stays at the host
> Summary: sim `snapshot_rights` fails about 2.5% of seeds since history-3 (bound 2, purge on replace: a writer's replaced body is still live at the host after the end of the scenario); one seed of the same scenario also runs node 0 to about 0.99 of the state bound.
> Priority: normal
> Tags: sync, engine, tests

- Seeds 389993699656, 389993699688, 389993699702, 389993699714 (`AuthorOrAdmin bound 2`) and 389993699723 (`Writer bound 2`): "body of node 2 at the host false, should be gone true". They fail on main from e380973a6 (the cover rule) on and pass at 1463b1fea (before thing-history step 3); fbc12a15c alone does not build. Replay: `osis_sim::replay("snapshot_rights", <seed>)`.
- Seed 389993699705: node 0 (the admin) stores about 4.7x what it must hold, at 0.99 of the `STATE_*` bound on main (calibrated at 0.47), and 66 bytes over it under the `admin` purge default. State kept at the admin that hosts dropped is the thing to look for.
