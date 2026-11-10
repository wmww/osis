# epochs-side
> Summary: Mishaps on the epochs differential side fix.

- The brief named issues/epochs-model-side-differs.md, which was not on main yet (it came with gate-shape; the stack review deleted it: the issue's seed passes with this fix).
- roles-model `epochs` has no `Shrink` for `World`, so a differential failure prints a 19-item world to shrink by hand.
