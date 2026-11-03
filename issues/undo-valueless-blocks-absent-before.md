# A value-less write blocks "Absent before"
> Summary: Engine and crdt-model differ on whether a write held value-less (expired, purged) blocks undo's reset of a position absent before: the engine blocks, so the undo writes nothing and the value stays; the model resets. The spec's wording favours the engine, the sense of undo the model. Owner-level choice.
> Tags: crdt, tests

Rule: spec/crdt.md §4.6 "every value-carrying write (§4.7) and explicit `W` P holds"; §4.7 "A value-carrying write may be held without its value", so read literally it blocks. `only_from` (core/crdt/src/undo.rs:94) counts registers, cases and creations whatever their value; the model's `valued` (core/test/crdt-model/src/undo.rs:386) skips value-less ones and its header calls that a read-equivalent choice. It is not.

Run (throwaway test): struct absent before; c writes field 1 = 7; another's later write to field 2 went value-less. Undo of c: engine writes nothing, reads `{1: 7}`; model resets, reads absent.

Neither differential reaches it: `tests_undo.rs` never strips. Recommendation: not blocking (nothing reads the value-less write, and undo otherwise silently does nothing); then fix `only_from` and say so in §4.6.
