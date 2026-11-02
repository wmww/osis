# A text insert held after its delete gets no death
> Summary: under a relative keep bound, a text insert whose delete arrives first has no death at that node (`deaths` None, the delete's `ts` by the oracle), so a keep-at-most bound never drops its body. Honest history of two commits; spec/commits.md §5, spec/crdt.md §4.8.
> Tags: tests, crdt, engine, retention

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_seq_death_delete_first_spec_crdt_4_8` (order seed 1054).

Dating never covered text: the harness's untyped writes could not write one. `order::dating` skips `t:text.0` and `t:docs.0` until this is fixed (`skip_seq_death_delete_first`); remove that with the fix, which may show more of this family (a kept text in a map entry, list elements).
