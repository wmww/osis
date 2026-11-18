# keel-custody-readd
- X's forged rotations in the custody differential are not in `ix.role_on[(D, P)]`, though they carry seed boxes: enumerating an account's seed-box commits needs the account view's rotations as well (`custody::take_held_boxes`). Cost a debug round.
- A hand test on `Run::new(0)` must `r.lp.advance(1)` before its first act, or `Run::now` underflows (A's clock is one before the run's base).
- I pushed right after a rebase that pulled in engine changes and only ran clippy and the osis-engine tests afterwards. They passed, but the order was backwards.
