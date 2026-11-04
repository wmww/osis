# depth0-model
> Summary: Footguns met while model-checking depth-0 sealing.
- A TLC `.cfg` cannot write tuples or functions: instance constants need an MC module (`Depth0MC.tla`) and `<-`.
- TLC parses the spec at start; editing the .tla while a batch of runs is queued mixed model versions across results. Run from a snapshot copy.
- `pkill -f` with a pattern that also matches the invoking shell's command line kills that shell.
- The shared box sat at load 40-100: TLC throughput dropped 5x, so instances sized "a few minutes" took 20-60.
