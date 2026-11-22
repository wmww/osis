# Complaints: review-key-admin
> Summary: Mishaps met reviewing the key-admin branch.

- `tools/heavy --short` on a 200,000-world `tiny` search is stopped at the lane's cap and exits 2 with only a refusal line; piped through `rg` the refusal was filtered out and the loop looked like it passed. Run model searches in a hold, unpiped, to a log.
- `TinyStats` prints a checks map that lists every property at the world count, so a property's hits must be read from its FAIL/NOTED lines, not the map.
