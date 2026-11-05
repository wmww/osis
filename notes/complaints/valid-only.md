# valid-only
- Item brief suggested "valid parts" for undo's in effect; a per-aspect rule (the obvious has_state analog) broke `osis` `commits::in_effect_is_whole_commit_spec_crdt_4_6`, a deliberate honest case only the `osis` crate tests. Grep every crate's tests for a rule's name before changing it.
- Any signer can write valid parts on its own things, so "all parts valid" alone never makes a stranger powerless: the rule had to tie the undo's valid part to the target's aspects.
- Review: the order oracle's seed variables are `OSIS_ORDER_START`/`_SEEDS` and the ephemeral ones `OSIS_EPH_*`; only reading the harness says which.
