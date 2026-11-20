# a2-spec-review
- The evidence model's default tests and both sampled properties pass with the leaf rule narrowed to commits stamped before the lowering only in `_plain` (random seed 11), and with the addendum-leaving rule disabled in none: each new rule needs its own hand test before it counts as checked. Run a one-line mutation per new rule in review.
- The model's oracle is `roles_model::paths::evidence`, shared by roles-model's own tests: a change to what the closure takes is a roles-model change even when the stage is held-model's.
