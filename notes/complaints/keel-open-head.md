# keel-open-head
- `Engine::snapshot` maps a waiting snapshot (`MayWrite::Later`) to `Error::Permission`: a test expecting "waits" has to read an error, not `None`.
- The model's `random_world` draws shift whenever a policy writes one item fewer, so an issue's shard seed (epochs-differential-thief-readd) reproduces only against the model at the commit that found it: keep the printed world in the issue.
- 400-seed holds don't map onto `epochs_model_agrees_large` (sharded, size fixed by `OSIS_FULL`): ran it at small size under 20 `OSIS_PERM_SEED` values instead.
