# Branch crdt-leftovers: decide, merge or delete
> Summary: branch `crdt-leftovers` on origin (parked, not merged): attempts at issues/removed-text-entry-keeps-key.md and issues/list-element-snapshot-before-expiry.md. A review said neither commit is ready. Finish it or delete it, then delete the branch on origin and this issue.
> Tags: crdt, retention

Pushed so the work isn't lost; three commits, 23 behind main when parked, so expect a real rebase. It may well be simpler to start over from the issues, with what this branch learned.

- Commit 1 (a reset of a dot drops bare anchors): leaves state, digests and snapshot bytes differing by arrival order in one corner, reads equal (`seq_compact` seed 7410006), against spec/requirements.md Deterministic. Needs Tess's call, or a sweep at compaction.
- Commit 2 (a value-less mark on a list creation): has the gap in issues/list-mark-lost-on-fall.md. Simplest rule left: value-less as its own state bit.
- Worth keeping either way: the oracle `order::arrival_order_list_expiry_large_spec_crdt_4_7`, which found issues/list-expiry-harness-seeds.md on main (look at seed 7520036 first: possibly a value kept past its expiry).

When done, or on deciding not to merge: `git push origin --delete crdt-leftovers`, delete any local branch, delete this issue.
