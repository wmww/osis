# Custody differential: the engine lacks a seed set the model holds
> Summary: osis-engine `rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4` fails on main: "t7 node B, account P: seeds held: engine {...}, model {..., {11, 30}}" (a node holds one seed set fewer than the custody model says).
> Priority: normal
> Tags: tests, engine

Fails on main at 52c6a11d1 with `OSIS_CUSTODY_START=146887569055 OSIS_CUSTODY_SEEDS=1` (`cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`): `t7 node B, account P: seeds held: engine {{}, {11}, {11, 26}, {11, 26, 30}, {11, 26, 43}}, model {{}, {11}, {11, 26}, {11, 26, 30}, {11, 26, 43}, {11, 30}}`. Found by the gate of s1-streams (sync only), replayed on main's own binary (`tools/bin-at`) with the same text. Either the engine drops or never builds the seed set {11, 30} (spec/permissions.md §5.4), or the model's expectation is wrong; not yet looked into. May share a cause with the other custody issues (issues/custody-*.md).
