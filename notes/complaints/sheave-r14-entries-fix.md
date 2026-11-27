# sheave-r14-entries-fix
> Summary: tools/land lost a race with a helper's push during its own policy run; the trace's delivery numbers restart per fixture world.

- `tools/land` fetches, then runs `tools/policy.py --baseline` (over 2 minutes on a loaded box), then pushes: a helper landed in between, so the push was refused non-fast-forward after the whole check. Fetching again right before the push (and refusing with the rebase hint then) would save the rerun.
- `OSIS_SYNC_TRACE` on a test built on a cached fixture (`siblings()`, `fixture_with`) prints the fixture's deliveries and the test's with delivery numbers starting again at d1, so `grep d68` matches lines of two worlds. A world label in each line would prevent misreading.
