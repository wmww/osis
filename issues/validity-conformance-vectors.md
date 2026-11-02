# Judgment vectors cover a first slice only
> Summary: `core/test/vectors/judgment/` (format: its README; generated and replayed by osis-node `tests/it/judgment.rs`) holds the roles model's reference scenarios and one scenario per rule family; still missing: the order harness's other shrunk seeds and pinned histories, epoch starts (no roster-snapshot scenario yet), referenced blobs (pages, chunks: the generator asserts none), multi-label bundles; each case still lists the setup commits' bodies.
> Tags: tests, permissions, retention, spec

## Left
- Replay more pinned histories as `Scenario`s: order harness seeds in `order::arrival_order_found_histories_spec_crdt_4_6` (1558, 1053, 1173, 93004, 12161, 12236, 61165, 583175, 15085, 2700027) and the other order.rs pins (7855, 1291, 1006, 1042, ...). Each is a few lines, but a file shares one setup (`judgment.rs` `SEED`, 1038): a history pinned under another seed is replayed under 1038 only if it still shows its bug there (check), else it needs its own file.
- Roster snapshots and epoch starts (every `start=` is `-` today), `until`, invites, ledgers: scenarios exist in roles-model `snapshot.rs`/`edges.rs` but need translating to engine steps (abstract ts and receipts).
- crdt-model's pinned cases (`tests/props.proptest-regressions`) are join properties, not judgments: no vector.
- Referenced blobs (pages, chunk trees, linked header lists) as bundle blob records without entries.
- Size: a file's bundles share one `setup` header (about 26 KB of hex), so a history adds 2-4 KB of bundle plus about 4 KB of expected fields per order; the setup commits' `body`/`aspect` lines repeat in every case. If files grow, judge the setup once per file or shrink it (fewer identities per scenario).
