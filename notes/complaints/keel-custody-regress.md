# keel-custody-regress
- The brief called a custody-property failure a regression since 3fd453937; it was not. The gate seeds properties from a random offset (tools/test_select.py), so "passed at X, fails at Y" means two different seed ranges. Before bisecting, replay the failing seed against both ends (`tools/bin-at`); here every failing seed failed at 3fd453937 too.
- The failing seed lived only in another agent's scratchpad log (covdrops-k7q/props.log). A brief for a property failure should quote the seed (the replay line) it saw.
- Custody property failures run ~1 world in 300-500 at large size; 200 gate seeds hit one about half the time.
- Bundling the model searches, perm large and rotation:: properties into one `tools/heavy` hold overran its limit (706 s wall, 598 allowed): one hold per run.
