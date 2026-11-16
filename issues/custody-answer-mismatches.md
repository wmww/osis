# Custody differential: honest answers and t re-keys differ from the model
> Summary: `rotation::tests_custody` large fails in about 1 world in 500 on what an honest node owes: the engine's plain rotation answers more lines than roles-model `custody` (a merge X certified, or a descendant of a line already answered), or skips a t re-key the model makes. The same seeds fail at 3fd453937, so the gate's random seed offset hits them by chance.
> Priority: normal
> Tags: engine, tests

Replay each with `OSIS_CUSTODY_START=<seed> OSIS_CUSTODY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`:
- 7719005588: t7 C answers `{1}` and X's merge `{1, 17}` (certificate #21); the model answers `{1}` alone.
- 7719005338: t13 A answers `{8, 12, 13}`, `{12}`, `{12, 13}`; the model `{12}`.
- 7719004994: t8 C makes a plain rotation answering `{1, 8, 13, 25, 31}`; the model owes none.
- 91234501198: t13 A answers `{1}`, `{1, 9}`, `{1, 9, 17}`; the model `{1}`.
- 7719004605 (t14 B), 5550001190 (t5 C): the node does not re-key t; the model does.

Open: which side follows spec/permissions.md §5.5 (answers owed; a merge named by a certificate where it joins a line not followed) and the t re-key rule (notes/engine-validity-epochs.md). Fix the side that contradicts the spec, with a constructed test of the minimal world.
