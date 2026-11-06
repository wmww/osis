# Branch crdt-leftovers: decide, merge or delete
> Summary: branch `crdt-leftovers` on origin (parked, not merged). Only commit 2 (8ca8275f, a value-less mark on a list creation) is left of use, as a reference for issues/list-element-snapshot-before-expiry.md and issues/list-mark-lost-on-fall.md; when those are redone or dropped, delete the branch on origin and this issue.
> Tags: crdt, retention

- Commit 1 (removed text keys): superseded by spec/crdt.md §5.6 Bare anchors (branch removed-keys).
- Its oracle `order::arrival_order_list_expiry_large_spec_crdt_4_7` is on main.
- Commit 2 (a value-less mark on a list creation): has the gap in issues/list-mark-lost-on-fall.md. Simplest rule left: value-less as its own state bit. Its tests_life.rs cases may be worth taking along.

When done: `git push origin --delete crdt-leftovers`, delete any local branch, delete this issue.
