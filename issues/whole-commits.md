# Whole commits: cover strips and the sealed-sections call
> Summary: What is left of notes/whole-commits.md (Left to build): parts dropped as covered do not strip, because a new reader cannot tell a part missing from its rewrite from one still to arrive; so a purge-on-replace part beside a live one stays in every sync store (a Deletion requirement leak), and a mixed commit's covered part keeps costing storage. Needs the "covered by a held snapshot's tables" rule first. Also open: whether a node opens sections only of things it syncs.
> Priority: normal
> Tags: engine, sync, security, spec

Built: one blob per commit, one expiry, apply never waits for a part; the strip for parts gone for good (purged, past bounds, destroyed), judged per blob (spec/sync-judgement.md §2 Per blob, notes/whole-commits.md Strip).

## Cover strips
- **Leak**: a part replaced under purge on replace beside a part that stays (one commit, two aspects) is dropped locally, but the shared blob keeps its section at every node holding the commit, readers' and unread stores alike, recoverable from the device (`deletes::a_part_purged_on_replace_is_unrecoverable_from_the_sync_store_spec_commits_5`, ignored until this lands). spec/requirements.md Deletion: granularity is one edit of one aspect, purge on replace is prompt.
- **Why not built**: stripping a covered part leaves new readers with a header listing it and no body anywhere; they count it missing and fetch it for good (tried: every pairing test then failed its "must-hold a caught-up reader lacks" check on node roots' `holds.0`/`tickets.0`).
- **Rule to add** (spec/commits.md §5 Covered): a part not held that a held valid snapshot of its aspect reaches by its tables (spec/crdt.md §8; `retention::snapshot::reaches`) counts as covered by it, not missing and never fetched; missing again once no such snapshot is held. Then `Engine::blob_gone` counts parts dropped as covered too, a strip waits for a coverer under the sync ID (own store) or shown at the source (deletes), and for `MAX_DRIFT` past the keep bound (`Dropped::hosts_from`).
- Then fold the strict-subset clause (spec/sync-judgement.md §2) into Per blob: a blob lacking a part this node still needs loses.

## Sealed sections
Whether a node opens sections only of things it syncs: opening sections of things it merely has the secret for lets a purged part be read for good from a sync ID where no request arrives; not judgeable at open time (a commit creating a thing and the strong to it carries the thing's record in a section whose thing the receiver does not sync until that strong applies), so it needs held blobs reopened as the sync set grows.
