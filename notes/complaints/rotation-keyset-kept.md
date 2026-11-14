# rotation-keyset-kept
- The issue's probe found no covered drop of a role-class body because node-sync's label pass drops only under content snapshots and the trigger never writes role snapshots: only `compact_now` (test hook) drops role-class bodies, though spec/commits.md §5 lets any compliant node do so. Cost a while to find; worth a line in the issue template ("which driver drops this?").
- `Engine::drop_body` skips keep bounds (callers judge them), so a test reproducing a covered drop must mirror node-sync's `CoverPass` (covered + `drop_from`) itself.
- `tools/policy.py` ran over 3 min; a foreground call got moved to the background.
