# epoch-intro-forget
- No debugger (gdb/lldb/perf) on the box: a hung debug test was located only by eprintln of backtraces per transaction and per commit.
- The first repro (a team not listed in g) hung `settle` for 10+ minutes instead of failing: `SETTLE_ROUNDS`/200k messages is no bound in time when each step is a sampled index check. See issues/released-team-unlisted-label-loop.md.
- Review: a test whose `cargo test ... | grep` foreground call ends early (grep -m) leaves the test binary running; two hung probes ran 11 min unseen. Write probe output to a file instead of piping.
- Review: telling a release-build loop from main's needs the debug index checks off; there is no switch, so the probe patched `check_rebuilt` behind an env var locally. A test-only way to run a Net without the sampled checks would help.
- Review: the test checked the index only after a restart, which re-derives `own_keys`/`keyset_parts` on its own, so two of four planted faults passed; check before the restart too. `shown` was not in `check_index`'s tables at all.
