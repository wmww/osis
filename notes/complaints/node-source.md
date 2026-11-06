# node-source
- Renumbering the header `form` values (commit 1 -> 0, session [2, n] -> [1, n]) reshuffled every commit ID and broke a seed-pinned order test (`purged_snapshot_copy_after_flip_seed_34000`: another stale value showed under the same excused flip). Kept the old values instead; worth knowing before any header-byte tidy: a pinned scenario is pinned to commit IDs too.
- A `git grep -o -iE ".{0,100}word.{0,80}"` over the repo ran past 2 minutes (the fuzz corpus and vectors are large single lines); plain `-l`/`-c` then a small script per file was instant.
- Stale "node-form" wording was spread over the engine notes, permissions.md, sync.md and ephemeral.md long after step 2 made every content commit session form; a step that changes a concept should grep notes for its old name.
- Review: the fuzz workspace did not build on main (`inbox` target, `InboxPayload::to_value` became a Result); nothing builds it per branch, so it rots silently.
- Review: `rejects_foreign_stamps_in_writer_delta_spec_3_3` kept passing on a 15-byte source after the kind went, rejected for its length instead; class-only `rejects(..)` asserts hide such shifts, message checks would not.
