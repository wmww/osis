# a3-spec-review
> Summary: Mishaps met reviewing A3's spec draft and its model.

- held-model's `Runners::AnyHolder` models no right at all (every holder runs every target), so a hand world can show the draft's runner rule failing only through the `Remover` control; worlds where the draft and the model disagree are invisible to the properties.
- `Stage::set` builds a rule from `Rule::listed` but each stage overrides `keys_open`: a test setting `keys_open` before `Stage::set` is silently undone; set it after.
- The model's remover keeps its own leaves for good (`State::held_leaves` seeded with `mine`), which no real node does: it can hide a leaf that left everywhere else.
