# m1-whole-review
> Summary: Snags met reviewing the paths model (roles-model `paths`, `vouches`).

- `vouches::shrunk` on one random world ran past 10 minutes on one core with no output (piped into `head`, so nothing showed): probe a failing world by printing it and its reference, never by shrinking it first.
- A noted (counted) property printed as `FAIL ... (shrunk)` in `paths` runs, beside an empty `failing checks {}`; it now prints `NOTED`.
