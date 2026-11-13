# Engine: validity
> Summary: Index of the engine-validity-* notes on keeping every delta's validity, and so every read, a function of the held set (spec/permissions.md §5, spec/crdt.md §4.6). The spec states the rules; these notes keep reasons, costs and tests.

## The notes
- notes/engine-validity-rejudge.md: what is judged again, and how cheaply.
- notes/engine-validity-epochs.md: the epoch rule.
- notes/engine-validity-rebuild.md: un-merge and re-merge by one rebuild.
- notes/engine-validity-snapshots.md: snapshot authority and carried writes.
- notes/engine-validity-uncover.md: covered bodies going missing again.

Elsewhere: reasons and Tess's decisions (notes/permissions.md Snapshots and history, Revocation, Implementation), invalid bodies dropping (notes/engine-retention.md Invalid bodies), suspect flags (notes/engine-suspects.md).

## Principle
Validity is a function of the held set, never of arrival order: an invalid delta changes no value, and a node that held it reads as one that never did. So every judgment input is held or persisted with its commit, re-judging follows what changed, and every change of what counts goes through one rebuild from the held valid bodies.
