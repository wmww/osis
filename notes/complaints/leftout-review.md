# leftout-build review
> Summary: merge-branch land's reread merges main's known_failures but not main's test_cost.txt, so a NEW-COST shown on main and raised there still blocks the land.

- The gate flagged osis-crdt/osis_crdt NEW-COST (269 G against 72); main's binary counts the same, so the line was raised on main. `tools/merge-branch land` rereads the summary with main's known failures but HEAD's test_cost.txt (`reread`), so it still refused, and the land needed `--fixed` for a failure the branch never had. Prevent: `reread` takes the larger of HEAD's and main's line per binary (or main's file merged like known_failures).
