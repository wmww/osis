# lost-access-wake
> Summary: small footguns met while arming the lost-access trigger's wake.

- No obvious "lost-access oracle" in notes/testing.md: `grep lost` finds only sim prose; ran the permission sim-sweep scenarios instead.
- The test harness `Net::advance` ticks every node regardless of its requested wake, so net tests cannot show a missing wake: assert on `Action::Wake` from `handle` instead.
- `claudewait` needs the exact task ID; a mistyped one just says "unknown task ID".
- Review: none new; the spot-checks (disable re-listing, disable the wake) each fail the new tests as expected.
- Review gate took about 8 min under a load average near 30 from other workers (mostly a cold-ish `clippy` check of the GUI deps).
- Rebase onto main (sync-audit, link-stranded) conflicted in `tests/it/sync_review.rs`: both branches appended a test at the file end; kept both.
- The disk filled (234G, 0 free) mid-build after the rebase; tests and gate could not run.
- Rebase onto main (sync-audit, link-stranded) conflicted in core/node/tests/it/sync_review.rs: both branches appended a test at the file end; kept both. The first `cargo test` after it then failed writing a fingerprint: disk full.
