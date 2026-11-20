# held-model: a leaf of a lowering that cuts nothing strands a reader
> Summary: Under `Rule::listed` a reader waits for the leaf of every held lowering whose edge a body rests on, a removal that takes no write away included; only its remover holds that leaf and no errand carries it, so the reader pends where the node holding everything judges invalid (notes/evidence-model-findings.md 27; `one_sync_id_reader_judges_as_everything_large` at start 0, random seed 76).
> Priority: normal
> Tags: tests, held-model

Repro: the `_large` property from start 0 (`cargo test -p held-model --test it -- --ignored one_sync_id_reader_judges_as_everything_large`), world `random(76, 14)` under `Rule::listed`, step 10, D's reader on commit 8.

Proposed (model first): `World::reads`/`pend_leaf`/`req_leaves` count a leaf (R, t) only for a commit whose needed level R takes away (a held chained write on R's edge giving it, ordered before R: reach's witness), as a list is read only for a cut (spec/permissions.md §5.2; README OPEN 12's bound). Then the leaf of a non-cut is evidence of nothing and nothing waits on it; check P1, P4, P7 on `Rule::listed`'s worlds and a hand world of this shape.
