# signing-6d
> Summary: Where the account switch stopped: built, tests left to port, and footguns.

Built: `Core::me` (account authors commits), `Osis::create` makes an account, pairing grants on D, `home()`, seeds re-taken at open, inbox sealed to and opened by the account, a grant's copy under the account's D, connection proofs by epoch key (`Engine::account_key_open`), own-write checks read `Origin::Local`.

Footguns: a test binary compiled while the box is loaded took over 15 minutes in the suite; hung tests look like slowness (no per-test timeout). A hang in a sync test: bisect by eprintln on `SyncEngine::step`, then `step`'s parts; nothing else prints stacks here (no gdb, unsafe forbidden).

Mishaps: `--include-ignored` on osis runs tier-2 too (values_past_limits_huge). Test binaries capture stderr: `--nocapture` before any counting probe, or a 6-minute run says nothing.
