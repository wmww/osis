# Handoff to the next coordinator
> Summary: State Fathom left when Tess wound it down: everything built is on main, no branch is pending, no critical issue is open; the next work in order, the open security items, the regular jobs, and the box (ostrich) setup. Delete once taken.

Read CLAUDE.md and notes/coordination.md first (design principles, the task loop, landing, regular jobs and their cadence). Opus for every agent; fable only when Tess says so for a job. Four agents at a time on this box (Tess). Questions for Tess are issues tagged `tess-call`.

## State
- Main holds everything; no task branch is pending and no worktree is claimed. No issue is `Priority: critical`.
- The account-forks redesign (custody: seeds boxed to device keys, the chain is the roster, merges only join) is built and on main: notes/account-forks-design.md. Its engine-vs-model differential (`rotation::tests_custody`) passes the gate's 200 worlds; at release size (2000, `OSIS_FULL=1`) a few worlds fail, each filed (below).
- The sync rebuild is on main; what is still stubbed: issues/sync-unbuilt.md; tests still owed: issues/sync-tests-owed.md.
- Tess's target state (no critical issue, no sync issue needing a major redesign, dogfood working, tests passing with fair coverage of the new code, no known n² blowups) is met as far as known.

## Next, in order
1. issues/switch-carries-words.md (security, narrow): after a device that sided with a thief switches back, its re-naming of its own old commits can carry the thief's write onto the honest side. A gap in the naming rule, not in custody or sides. Fix the rule, or bring Tess a limit to accept (as an issue, never a spec Limit).
2. Account-level own cover (spec/permissions.md §5.5 "Own cover", marked target; issues/account-signing.md step 2): rotations list the removed device's commits the rotator holds and write its own snapshot for what it forgot. The non-account half is on main.
3. The other custody follow-ups: issues/rebuild-learns-history-roles.md (rebuilt index differs from live; no data loss), issues/outsider-follows-other-honest-merge.md (an outside reader picks a different honest merge than the model; tie order), issues/thing-rekey-on-thief-side.md, issues/removed-device-reads-later-grants.md (role parts of later grants readable by a removed device until the next rotation; Tess accepted it for now as an issue, not a spec Limit), issues/account-tla-stale.md (low).
4. issues/clock-back-stalls-timers.md: a clock jumping back delays every scheduled sync wait by the jump (ignored repro in osis-sync `driver::`); one rule for every timer.
5. Gate cost: the custody property is 75 s of the properties stage (issues/gate-five-minutes.md); split or slim it. Test cost otherwise: issues/tests-4x.md.
6. issues/sync-unbuilt.md and issues/sync-tests-owed.md, by risk.

## Regular jobs
Cadence in notes/coordination.md (watchdog, test optimizer, cleanup, prose editor per agents spawned). Last of each: watchdog-6, test optimizer 16, cleanup-2, prose-2. Check the gate trend every few landings with `python3 tools/limits.py summary --since 24` (Tess: test cost doubles per unattended day); on ostrich gates run 4-10 min wall at load 20-40, over their limits mostly from load.

## Box and dogfood
- Box ostrich (16 cores, 30 GB; no public address, behind a home router; ufw off, no sudo). Devbox (the old public dogfood host) is down.
- A LAN-only dogfood channel runs here at pin cc38ab39f: state in `~/osis-dogfood-local/` (use `OSIS_DOGFOOD=~/osis-dogfood-local OSIS_DOGFOOD_UNIT=osislocal` with tools/dogfood-member.sh); units `osislocal-dogfood-host-cc38ab39f` (listening on the wifi address, port 4040/udp) and `osislocal-fathom-cc38ab39f`. A public host needs a reachable box (a VPS or a forwarded UDP port). Tess is not using dogfood. The old `~/osis-dogfood/` units are stopped; their dirs can be deleted.
- `wt` comes from agent-skills' reasonable-rust-builds 0.6.1 (release skips the marking build when the build key is unchanged).
