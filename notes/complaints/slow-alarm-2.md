# slow-alarm-2
> Summary: Snags met making the gate's per-test alarm load-independent.

- Saved gate logs carry no instruction counts, so the per-binary rule could be replayed on them only through the binaries a reviewer happened to keep (wi-gate's engine `it` pair).
- `tools/heavy --short` on a whole engine `it` (about 1,600 G, 500 CPU-s) is stopped past its cap and rerun in a hold: a whole-binary icount goes straight to `tools/heavy`.
