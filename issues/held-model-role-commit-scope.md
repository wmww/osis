# held-model drops every aspect when a role commit carries more than `roles.0`
> Summary: The held-model adapter takes every aspect out of the comparison when a role commit writes anything besides `roles.0` and `keys.0` (every flow grant, removal and record-only creation: `secrets.0`, `label.0`, `created.0`). Those parts change no role, so they can be placeholders as `keys.0` is; doing so compares about 3x the aspects but shows 3 held-model disagreements at `OSIS_FULL=1` plain from 5000, not root-caused.
> Priority: normal
> Tags: tests, held-model

The exclusion is a carve-out, not a rule: held-model's timeline reads only edge writes, a `secrets.0` delta's possession check (spec/permissions.md §5.2) judges that delta alone, and the model takes records from `things`, not `created.0`. The change (osis-node `tests/it/held.rs`): drop the `"role commit beyond roles.0"` scope rule and feed every role-commit part off `roles.0` as `Delta::Writes(vec![])`.

With it, `held_set_decides` compared 8179 aspects at quick (2220 without) and 222k at plain-full from 5000 (80k), and these seeds fail (replay: `OSIS_ORDER_SEED=<seed> OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain`, with the change applied):
- 5035 (RecordOnly): a removal of a record-only thing's first admin (`RemoveFlow` of the record edge, no entry for it): model says the role commit does not apply, the node applies it. Likely the model's reset-waits-for-its-creation rule meeting a record edge (spec/permissions.md §2: such a removal resets an entry of its own delta); model or adapter.
- 5059 (RecordOnly): validity of a `t:gone.0` write: model valid, node invalid.
- 5071 (Addenda): validity of a `t:reg.0` write: model valid, node invalid.

Root-cause each (model, adapter or engine), then land the change. Until then record-only and flow histories are judged by the keep-everything node alone.
