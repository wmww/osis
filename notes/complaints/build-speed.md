# build-speed complaints
- system76-scheduler was back on after an OS upgrade (enable symlink re-created at boot): every cargo run past its 60 s refresh went SCHED_IDLE, so builds beside any test run took 10-30x. Nothing in the repo showed it; the gate now warns. Needs Tess: `sudo systemctl disable --now com.system76.Scheduler.service && sudo systemctl mask com.system76.Scheduler.service`.
- My own measurement builds were caught by it too (an osis-engine lib rebuild: 28 s once, 330 s the next time, same CPU-s), so timings on this box are only comparable by CPU-s until it is off.
