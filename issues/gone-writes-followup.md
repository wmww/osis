# Gone writes: what is left of the rewrite
> Summary: spec/crdt.md §4.7 (an expired or purged write has no effect on the read) is built through crdt, engine and held-model; left: deleting suspect repair (no case left, spans osis-sync and the wire) and Tess's call on a requirements line.
> Priority: normal
> Tags: crdt, engine, sync, tess-call

Built: gone writes removed from each body before it joins; no value-less form in state or on the wire (a map dot's keyless record holds its removal alone, rejected on decode otherwise: spec/crdt.md §3.3 rule 7, §5.6); a purged part is listed while a body of it replaced at its own `ts` would be in history, never past its expiry (spec/commits.md §7 Listed parts), and its commit is forgotten only once none of its purged parts is listed (`retention::purged_unlisted`, a memo-clock wake at the bound). A part dropped pending at its expiry flags nothing. A held snapshot's carried bound (`retention::snapshot::Carried`) is the counters of every write its body holds, which expiry in place reads; expiring snapshots' copies end at their expiry for every write of a dot, value-carrying or not (`snapshot::expiring_copies`).

The purge re-snapshot (spec/commits.md §5 Purge, `purge::owe_resnapshot`) keeps a job: a node that dropped, as covered, the body a purged write replaced takes no copy of it again, so only a writer still holding it brings it back by re-snapshotting (`resnapshot::a_compacted_node_reads_what_a_purge_brought_back_once_a_writer_resnapshots_spec_commits_5`).

Left:
- **Suspect repair has no case left**: `Why::Uncovered` flags, suspect lists (osis-sync `inbox/suspect.rs`, wire Suspect message, spec/permissions.md §4 Suspect, Suspect list), `Engine::repair_suspect` and spec/sync-compaction.md §1 Repair. A flagged node lacks a body that counts as never received and is fetched from any holder; a writer holding only the body's effect holds it through a valid snapshot, which the flagged node syncs too; where only a reader holds the body the writer's snapshot is the poorer state and changes nothing. No fixture shows a repair changing a read. Delete it whole (spec, notes/engine-suspects.md, proto, sync, engine, tests), after sync-rewrite lands (it touches osis-sync).
- spec/requirements.md Decentralization's arrival-order limit for expiring edits no longer describes a divergence: Tess's call whether to drop it.
