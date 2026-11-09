# held-model does not judge `required^.0` and `addenda.0` reads
> Summary: held-model takes `required^.0` bodies as rules and `addenda.0` bodies as entries, so their reads (join of the valid bodies) are compared by the same-engine keep-everything node only.
> Priority: low
> Tags: tests, held-model

The order harness's held-model comparison (`core/node/tests/it/held.rs`) compares every content aspect's read and every roster, but not the reads of `required^.0` and `addenda.0`: `hm::Delta::Required` and `hm::Delta::Addenda` carry the decoded rules and entries, which decide validity and vouching, not the crdt fragments the read joins. A wrong join or un-merge on those aspects shows only through the effects that are compared (broken parts, counted addenda) or not at all.

Fix: carry each such body as a crdt-model fragment beside its rules or entries (the model derives the rules from the fragment), let `evaluate` read them like content, and compare their reads.
