# keel-prose-refgraph
- `grep -E` here is ugrep: a long alternation with `.{0,120}` context fails "exceeds complexity limits" and prints 0 matches with exit 0; a Python scan was needed to list term uses with context.
- Code comments still in old terms (left alone, not cited sections): `Opening::Taken` doc says "an inbox blob" (core/sync/src/streams/mod.rs), "home sync ID" (core/engine/src/sync_ids/published.rs), `released.0` (core/engine/src/retention/history.rs module doc), `devices_of` and `CreatedAccount::devices` (flows/account.rs).
