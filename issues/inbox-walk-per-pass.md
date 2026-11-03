# Each pass walks every unexpired inbox blob
> Summary: Handled inbox blobs now stay past the deposit budget until they expire, and `inbox_certificates` and `vet_inbox_hints` walk all of them each pass, so a person's pass cost grows with the grants of the last 90 days.
> Tags: node-sync, scale

Before the stamp (`stamp_inbox`) a label held at most its budget of them per host. `inbox_certificates` re-checks `held_whole` per blob though its comment calls such a blob done; a later `label.0` is what brings one back, so a done mark needs that trigger.

Probe (dev profile, machine loaded, Bob alone, 3 passes): 40 blobs 36 ms, 240 about 1 s, 320 about 2.3 s; superlinear, not profiled (`perf` refused here). Burst of 400+ grants from one sender in one probe took minutes of wall time, most of it the sender's own `grant` (about 1.8 s each at 320 things it owns, loaded): not looked at, may be on main too.
