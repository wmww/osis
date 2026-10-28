# Refusing a snapshot whose `Authors` differ from the held claim is order-dependent
> Summary: `note_authors` refuses a snapshot naming another author or `ts` for a `Commit` source than `Core::authors` holds, but that claim can change when a commit arrives later (the source's own commit, or a lesser import of it), so a node holding the snapshot first keeps it and a node holding the commit first refuses it.
> Tags: security, node, validity

spec/crdt.md §8 makes such a snapshot bad input. Cases: a hostile snapshot naming a false claim for a commit-form commit C, then C arrives (kept; with C first, refused); a node holding only the later of two imports of one origin (spec/permissions.md §7, hostile importer) snapshots honestly, and a node holding the earlier import refuses it while one taking the snapshot first keeps it. The judgment of carried writes still follows the held claim either way (groups are re-judged when it changes); only the held set differs. Hostile-only.

Options: make a mismatch not bad input (the held claim governs; a snapshot's entry is used only where nothing held claims the source, the least such claim among held snapshots), which needs per-snapshot claims to re-derive on a forget; or keep refusing and also refuse, on arrival of the commit, nothing (accept the divergence as the cost of hostile input).
