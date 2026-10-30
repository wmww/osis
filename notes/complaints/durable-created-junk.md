# durable-created-junk
- Brief asked for sim-sweep "permission/compaction" scenarios; there is no `permission` scenario or group (`--list`), so I picked the revoke/demotion/coverer/equivocating ones by hand. Briefs could name scenarios exactly.
- The issue assumed a writer delta could carry losing junk; the writer-delta codec already refuses foreign stamps and slots, found only by trial. The real durable hole was snapshots/imports of `/created` (now refused by header validation) plus resets/untyped structure.
