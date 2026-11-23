# walk-current
> Summary: Mishaps met making the walk never read stale.

- Finding every stale read needed instrumentation: a `#[track_caller]` accessor logging its caller and a backtrace on a touched held set, and `#[track_caller]` on `Held`'s mutators to name the touch. A plain assert stops each test at its first hit (1,182 of ~1,200 failures were one site).
- A full osis-engine test run took 5 to 10 minutes under the box's load (load average 25 to 50), several times the quiet-box figure.
