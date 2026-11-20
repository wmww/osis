# a2-spec
> Summary: Mishaps and slow spots met drafting A2's spec and extending held-model `evidence`.

- `explore_random` (every variant over 300 random worlds) is about 140 CPU-s: past `tools/heavy --short`'s cap, which stopped it after the build; run it under plain `tools/heavy`.
- `show_random` printed only the design rule's failures; it now takes `OSIS_EV_RULE` (a variant's name from `variants()`).
- The random generator writes addenda listing addenda and nothing; a rule keyed on what an addendum lists must say which listed commits count, or a writer's own unlogged addendum keeps another alive (P4-held in seed 214).
