# Deletion: remaining open questions
> Summary: One choice remains after purge rights, local erasure, two-factor hard delete and writer-derived tokens for ephemeral content were decided (2026-10-11/12): the default compaction policy.
> Tags: sync, crdt

Decided (do not reopen): three retention classes, purge granularity one (commit, aspect) delta, no fingerprint after purge, forward-secure deletion as a requirement, read access never deletes at a blind node, rotation decoupled from deletion, purge rights author-or-admin, hard delete at blind nodes by per-entry token plus current writer signature or by the admin label key, `purge`-class tokens derived from the writer role secret, eager label-key rotation on removal, grace period default 30 days (covers only non-ephemeral soft retires now), no debounce on partial purges (one snapshot per edit), local erasure by key tree and random chunk keys (notes/constraints.md, notes/crdt-sync.md, notes/sync.md, notes/permissions.md, notes/local-store.md).

## 1. Default compaction policy
`undefined` retention lets nodes drop superseded bodies by local policy; compaction is what drops them at blind nodes (notes/sync.md). Candidate default: trigger on the ratio of superseded to live bodies under a label, done by the writer that notices on its next write, with a randomized delay against a thundering herd. Readers never drop locally: a local drop without a label retire gets the blob re-offered on every fallback reconciliation. Write into notes/sync.md once confirmed.
