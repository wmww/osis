# Forks worlds: an index rebuild judges a role commit otherwise
> Summary: On fathom-custody-engine, 14 of 2000 forks worlds (`OSIS_FULL=1`, seeds 245, 378, 509, 534, 737, 1163, 1217, 1239, 1369, 1417, 1498, 1575, 1776, 1905; the same in both `engine_agrees_with_forks_model_large_*` and `_switching_back_*`) fail the debug index check: rebuilt from the commit records, a role commit's parts are all invalid where the running index has them valid. Not yet checked against main or the branch before the re-seals.
> Priority: critical
> Tags: engine, tests

- Replay: `OSIS_FORKS_START=245 OSIS_FORKS_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4`.
- Same seeds with and without the settle's switches, so it arises before the settle. Suspects: custody state a rebuild reads otherwise (seeds taken up as boxes apply mid-transaction, `Indexes::unpublished`, the account taken up before or after the judgment), or a judgment that depends on arrival order. A rebuild must judge as the running index does (validity is a function of what is held).
- The default sizes (200 seeds) do not reach it.
