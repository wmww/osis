# held-model does not judge `retention^.0` and `addenda.0` reads
> Summary: held-model takes `retention^.0` bodies as settings and `addenda.0` bodies as entries, so their reads are compared by the same-engine keep-everything node only.
> Priority: low
> Tags: tests, held-model

The order harness's held-model comparison (`core/node/tests/it/held.rs`) compares every content aspect's read and every roster, but not the reads of `retention^.0` and `addenda.0`: `hm::Delta::Retention` and `hm::Delta::Addenda` carry the decoded setting and entries, which decide history and vouching, not the crdt fragments the read joins (until thing-history step 3 the engine writes `required^.0`, fed as a placeholder). A wrong join or un-merge on those aspects shows only through the effects that are compared (broken parts, counted addenda) or not at all.

Fix: carry each such body as a crdt-model fragment beside its setting or entries (the model derives them from the fragment), let `evaluate` read them like content, and compare their reads.
