# held-model complaints
> Summary: Mishaps met building the independent held-model crate.

- A new model crate needs three hand edits outside it (workspace members, `is_model` in tools/policy.py, `MODELS` in tools/spec_map.py); nothing points from one to the others.
- spec/commits.md §5 and spec/crdt.md §4.6-§4.8 restate the same rules with different wording (death dating, grace, live writes), so a fresh reader has to reconcile them before modeling anything; see core/test/held-model/AMBIGUITIES.md.
