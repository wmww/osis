# masked-lowerings
> Summary: Mishaps met showing two masking backdated lowerings as disputes.

- The heavy lock queued each story search for several minutes behind other branches' holds: four 13,000-to-65,000-world runs took most of the wall time while using a few hundred CPU-s each. Chaining them in one background call kept the queueing to one wait per run but not less.
- The issue's candidate rule read sound on paper and failed on the first probe: the second masking demotion finds the share already dropped and drops nothing, so "a lowering that applied with drops" sees only one of the pair. A probe printing `Reading::dropper` for the issue's world was the quickest check of any proposed rule.
