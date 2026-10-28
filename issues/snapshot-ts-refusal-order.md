# Refusing a snapshot whose dot `ts` differs from a held commit's is order-dependent
> Summary: `note_authors` refuses a snapshot carrying a stamp or creation `ts` for a dot of a held commit other than that commit's `ts` (spec/crdt.md §8), but a node taking the snapshot before the commit keeps it, so held sets diverge on hostile input.
> Tags: security, node, validity

The `Authors` half of this was fixed (a snapshot entry naming another claim is not refused; the held claim governs, else the least snapshot entry). The dot `ts` check remains: snapshot first, kept; commit first, refused. Hostile-only (an honest snapshot copies the commit's `ts`). Options: not bad input (the held commit owns its dots and is judged at its own `ts`; the snapshot's copy of the dot joins with a wrong stamp, so check what the join does with one dot at two `ts`), or refuse nothing and accept the divergence.
