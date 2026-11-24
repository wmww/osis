# A writer's forged copy of another's write changes what it reads, unattributed and undetected
> Summary: A valid snapshot may carry another author's write under its stamp with another payload; copy order (spec/crdt.md §4.1) can pick the forged payload, so every reader shows the forger's value in place of the author's, with `changed` naming the author's commit and no history entry. A node holding both copies has proof (the author's signed delta, the forger's signed snapshot) but by spec never compares them. Should it?
> Priority: low
> Tags: security, crdt

**Decided (Tess):** an open issue, not built around. What a snapshot carries is its writer's word; to do: the API attributes a value to an author only where the author's own commit is held, else to nobody.

What any writer of the thing can do, by spec (spec/permissions.md §5.2 Copies):
- **Forge a value**: copy order decides each part by bytes, so the forger picks a winning payload and every node holding both copies reads it (osis-engine `retention::tests_forged`). The author's write is not dead (copies are one write, spec/crdt.md §4.8), so kept history shows no change and `Osis::changed` names the author.
- **Misname a purge author** (spec/crdt.md §8 facts are its word too): naming itself purge author of an admin's `author_or_admin` write and purging by author erases that write at nodes holding only the snapshot, until an honest carrier reaches them (osis-engine `retention::tests_carried::a_writers_misnamed_fact_lets_it_erase_an_admins_write_at_a_snapshot_only_node_*`): a purge-right escalation at snapshot-only nodes.
- **Un-hide**: hiding is payload (spec/crdt.md §4.8), so a forged copy of a removal naming other parts, or of a set element holding another value, dates a write's death later or not at all, against spec/commits.md §5 "one holding more judges no later", which holds for honest copies only.

Not wider than other snapshot powers: a writer's snapshot may carry a write no one made, under any stamp below its own, with the same read and `changed`.

Options: (1) as now, never compared; (2) a node holding both judges the snapshot invalid, or flags its signer, the read keeping the original's payload; (3) copies differing in value never join (the original wins wherever held). (2) and (3) make reads depend on whether the original is held; a fabricated write (no original anywhere) stays undetectable under any option.
