# A removal by an admin through a holder actor it cannot show waits
> Summary: a remover holding admin on A only through holder actor M, lacking the secret of the keyset Seal gives for M, writes a rotation failing Authority; its own node refuses the commit (`Permission`), so the removal waits, where the uniform rule says it goes alone.
> Tags: keys, engine

The rule (spec/permissions.md §3, spec/crypto.md §4 Seal): a removal always applies; a rotation
that cannot be made yet stays due and nobody that may rotate encrypts under A meanwhile. Built for
Seal waits (`flows::edges::demote_in`, `finalize_in`). Not for possession: `demote_in` does not ask
`rotation::possessed`, so where the remover's role runs only through M and it lacks M's current
keyset secret, the rotation's `secrets.0` delta fails Authority and `apply_local` refuses the whole
commit. Fix: write the removal alone there too (`recipients` Some and `possessed`, else alone),
with a test in `tests_possession`. A remover lacking a current secret of A still waits on purpose:
a removal alone would spend the audit lockout recovery needs (spec/permissions.md §3).
