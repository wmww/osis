# add-cost-review3
- The rebase's textual conflicts hid a semantic one: `Touched::is_empty`, new in labels-cost, did not know `roles` from add-cost, and git merged it silently. A struct's field-by-field `is_empty` has no compiler check that it lists every field.
