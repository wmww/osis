# fathom-rebuild-review-3
- The branch moved under the review (role duties rederived mid-read): a fix written for the old work-list duty was thrown away. Reviews of a moving branch should name the tip they judge.
- `LocalPeer::sealed` still runs `ensure_rotated` before sealing (the old node-sync's `uncovered`), so engine tests pass for rotations the rebuilt driver never makes; a driver-shaped helper (`tests_members::driver_duties`) caught the stale-box-below stall.
- `role_duty_due` erred (`UnknownThing`) on a destroyed thing with a passed `until`; one actor's error fails all of `Life` at every settle.
