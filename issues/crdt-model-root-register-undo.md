# crdt-model does not undo a root register's reset
> Summary: For a root register the model has no `remove_aspect` undo (it writes nothing) and undoes `replace` by the register rule (no write when something newer wins). Spec/crdt.md §4.6 and osis-crdt re-insert the pre-reset value in both. The undo differential never picks a root register, so this went unseen.
> Tags: crdt, tests

core/test/crdt-model/src/undo.rs: the reset rule is guarded by `ty.enc() != 0`, and the register arm needs a write; its header calls this a read-equivalent choice. osis-crdt: core/crdt/src/undo.rs:141 (`reg.reset` goes to `undo_reset`).

Run (throwaway test), base 1: undo of `remove_aspect`: engine 1, model absent. Undo of `replace 2` with a later write 3: engine 1, model 3. Spec/crdt.md §5.1 now states the rule (it read as if the register rule applied).

To do: fix the model from the spec and add `Ty::Register` to `types()` in core/crdt/src/tests_undo.rs. Owner may want to weigh whether undoing a register `replace` should overwrite a live later write (§4.6 says step-back is "never over a live later change" for register writes; composites' resets do wipe, notes/crdt.md).
