# eph-reverts complaints
> Summary: Workflow notes from tracing the eph-reverts seed.

- The issue's seeds passed on main; the cause showed only in a fresh 500-seed range. A seed issue goes stale fast, so keep the reproducer, not the seed.
- Tracing a host-side refusal took ad hoc eprintlns in node-sync (`entry_status`, `send`, `body_sends`). Nothing in the test API shows an upload's status codes or why a pass held a body back. A test hook listing the last status per (label, blob) would have saved most of the time.
