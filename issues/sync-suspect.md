# Suspect lists and repair are not built in the rebuilt sync
> Summary: No node sends Suspect lists (spec/permissions.md §4 Suspect list) and a received one is answered Ok and dropped, so the repair of spec/sync-compaction.md §1 never runs; the engine's flags (`Engine::suspects`, `state_digest`, `snapshot`) are built. Plan for its own osis-sync part.
> Priority: normal
> Tags: sync

What it costs: an aspect a node computed from less than another holder (a body dropped as covered counting as never received, a part pending at its expiry) stays apart until the next write of that data (notes/engine-suspects.md, The limit it backstops). Reads diverge only in those rare shapes; no data a writer holds is lost.

Plan (one part, e.g. `inbox/suspect.rs` or its own module):
- Sending: per (connection, member S), the flagged, not dormant aspects of things in S's closure with their state digests, most recently flagged first, chunked to `MAX_MESSAGE`, sent on S joining the shared set and whenever that list changes. `Engine::suspects` is a scan of `q/` rows, not stamped: a stamped value (or a feed of flag changes) is needed first so the list follows change.
- Receiving: a node that may write the aspect, past its first sync of S, whose own digest differs and that holds state, writes `Engine::snapshot` and logs it as any must-hold body; at most one snapshot per (state, reporting node), so a report no snapshot settles writes nothing more (old scenario suspect-repair-per-launch: not once per launch either, so that bound is durable); each judged entry a `DiagnosticKind::Repair`.
- Tests: a flag sent and cleared; a repair written once per state per reporter, across a restart.
