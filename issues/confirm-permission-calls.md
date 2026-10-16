# Confirm smaller permission calls
> Summary: Agent's calls in the permission design that the owner may revisit: hand-over identity by construction, link finalization, edge-admin purge, recovery card format, nodes as self-owned things.
> Tags: permissions, owner-call

- Hand-over: the new identity is owned by the new owner by construction, plus an acceptance snapshot (spec/permissions.md §7). Alternative was a frozen certificate bundle per record, which let ex-devices hand things out forever.
- Links: `until` and single use need a sharer device to write a real removal (spec/permissions.md §9). Alternative: drop both features.
- Edge-admins may purge (spec/permissions.md §8).
- Recovery card format (spec/permissions.md §9).
- Nodes as self-owned things publishing node cards under each label they sync (spec/permissions.md §4).
Reasons: notes/permissions.md.
