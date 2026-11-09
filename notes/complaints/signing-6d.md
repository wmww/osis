# signing-6d
> Summary: Where the account switch stopped: built, tests left to port, and footguns.

Built: `Core::me` (account authors commits), `Osis::create` makes an account, pairing grants on D, `home()`, seeds re-taken at open, inbox sealed to and opened by the account, a grant's copy under the account's D, connection proofs by epoch key (`Engine::account_key_open`), own-write checks read `Origin::Local`.

Footguns: a test binary compiled while the box is loaded took over 15 minutes in the suite; hung tests look like slowness (no per-test timeout). A hang in a sync test: bisect by eprintln on `SyncEngine::step`, then `step`'s parts; nothing else prints stacks here (no gdb, unsafe forbidden).

Mishaps: `--include-ignored` on osis runs tier-2 too (values_past_limits_huge). Test binaries capture stderr: `--nocapture` before any counting probe, or a 6-minute run says nothing.

Removing `Core::me`'s fallback did not fit: the scripted port (local branch `signing-6d-me-wip`) still leaves 264 tests failing, mostly hand-forged node-signed commits and bare peers writing, and one node-crate compile plus run is 5 to 20 minutes on a loaded box.
A seed number means nothing across commits: a baseline on main needs its own 100 seeds, not the same seeds.

Review: a sim seed's "live differs from rebuild" and a storm both traced to one branch; a trace with `OSIS_SIM_TRACE=1` over 7000 lines is the only tool, and the `--seeds 1 --from N --only X` run of a stale binary (a copy made before editing) is what let a bisect by code revert work.

The rebase onto fast-render left `views::pending_typing_makes_undo_pressable` failing (a memoised can_undo not re-evaluated after the undo commit): the core gate passes, the GUI steps do not.
