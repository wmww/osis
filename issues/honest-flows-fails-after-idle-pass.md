# honest_flows_wait_for_no_resync fails on some seeds since idle passes
> Summary: not a missed mark: the oracle compares blob IDs, copy counts and log order, and idle passes changed pass order. Fixed by the oracle-dice branch's oracle; delete this issue when it merges.
> Tags: tests, node-sync

Repro on main: `OSIS_SIM_FROM=4 OSIS_SIM_SEEDS=1 cargo test -p osis-sim --test it -- --ignored honest_flows_wait_for_no_resync`.

Traced with a blob's commit and parts next to each arrival, on main, seeds 731200 and 9000..9049 (16 of 51 fail), and seed 4:
- **Nothing arrives late.** In all 51, every (label, author, aspects) reaches the host at the same moments under both modes, and has the same commits with a live copy at the end. One extra moment, work sets only: a delete of a spare copy (731200, 6161000). No heartbeat differs: a run is about 2 h and the interval 6 h.
- **Other blob IDs (seed 4's 5 differences, most of the rest).** Same commit, label and moment. A label a change does not reach used to pass at every tick; now it passes when marked, so a node's passes run in another order and its seals draw from the random stream in another order. Seed 4, node feeS: full passes 35fb, 7fab, 878b, 9e6e, bc12, 878b; work sets 35fb, 7fab, 9e6e, bc12, 878b, in one moment.
- **Another copy stays (the 'D' entries, 731200).** Of two copies the higher ID goes, and a node's own certificate copy counts as neither (`judge`), so 2 copies or 1 stay by ID luck (9039).
- **One copy more under full passes (731200, 9009, 9013, 9030, 9041; only 731200 traced).** Commit cee82c under b962: RKB4 uploads a certificate copy in both runs. S75J's full pass then finds no part held under full passes and uploads a second; under work sets its pass places no copy of it. Probably a race with RKB4's copy reaching S75J (not logged). The label holds the commit either way.
- **Digest only (9035, 9045, 9049).** No arrival differs; the digest takes blob IDs and log order.

The method has teeth: with `downstream` cut from `engine_events` the comparison finds 277 differences on seed 0.

A label marked during a pass waits for the next step, at most one resync (61 s in the sim), never `pass_at`; oracle-dice's `PASS_AGAIN` makes that the same step.

Oracle-dice's head passes the same seeds plus 4 (52 of 52), and fails seeds 0, 4 and 731200 with `downstream` cut.
