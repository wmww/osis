# review-d2-held complaints
- `tools/heavy --short` stops a loop of several ~2 s property runs past its 115 CPU-s cap (a parallel search burns ~20 CPU-s per run): one `--short` per run, not one per script.
- A reference-excuse oracle is hard to judge from code alone: the probes that settled it (drop copies under one sync ID, one node, all; excuse every lowering) were five env switches on a wip commit; a standing `OSIS_PROBE`-style control list in the test module would save the next reviewer the rebuilds.
