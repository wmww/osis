# dogfood-filing
- `Osis::create` overwrote D's group.0 with an empty group, silently undoing what `create_account` listed (synced group, profile); found only because the host's own profile showed up in `invitations`. "Home stays under it" is unbuilt (issues/sync-unbuilt.md), so nothing refused that write.
- The CLI harness has no network, so cross-account CLI flows can only be tested at the library (osis-chat) with the commands checked for parsing and exit codes.
- The brief's scratch dir must be made before a backgrounded redirect into it: the first run wrote nothing and reported exit 0 from the wrapper.
- Review: the per-step commit-work check failed because a compaction snapshot of home's group.0 fires at n and not at 10n (body/snapshot ratio); per-step work attribution in scaling tests moves with compaction thresholds, so sum per kind.
- Merge: a held ephemeral body's memory charge was keyed per (sync ID, blob), so its entry under a second sync ID counted at bytes and let a second commit past the cap there; which sync ID opened first depended on fixture shape, so the bug surfaced only when an unrelated fixture change reordered deliveries.
