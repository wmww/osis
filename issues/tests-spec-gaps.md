# Spec rules without a full test
> Summary: MUSTs and refusal rules the spec-to-test map shows untested or only partly tested, by subsystem, with the crate that enforces each.
> Tags: tests, node, commit, server

notes/testing-map.md ("MUSTs and refusal rules") lists every rule; these are the gaps.

## node-sync (osis-node)
- spec/permissions.md §3 (removal placement): untested. `removal_rotates_spec_perm_3` checks that a removal yields `Delivery::First`, not that the removal and the new `/keys` reach every label the removed party could read, in the same sync, before any other upload (`flows/edges.rs` builds the delivery, `sync/deliver.rs` orders it). Test with a net-harness group of two labels: after the removal's sync, the server log of each label holds the removal entry before any later content entry.

## commit (osis-commit)
- spec/commits.md §1 (delta fits a blob): only a single delta over `MAX_BLOB` is refused (`projection_splits_by_size`); the struct or enum of many near-`CHUNK_THRESHOLD` registers, the case the rule names, is not built. Costly at full size (about 8000 fields): a test needs a builder hook for a smaller `MAX_BLOB`.

## node validity (osis-node)
- spec/permissions.md §1 (membership-class by admins): edges are covered (osis-perm `writer_cannot_write_edges`) and the writer side (osis `membership_class_refused_spec_permissions_1`); no received-side test of a forged non-admin `/moved`, `/was` or `/label` write being un-merged.

## server (osis-proto server session)
- spec/sync.md §5 (upload refusals): an oversized blob is refused by the message decoder (`field_sizes`); the session's own `TOO_LARGE` check (osis-proto `server.rs` `accept`) is unreachable through `ClientSession` and has no test.
