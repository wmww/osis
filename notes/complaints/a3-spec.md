# a3-spec
> Summary: Mishaps met while drafting A3's spec and its model.

- `tools/heavy --short CMD | grep ...` hid the lane's refusal (the run passed 115 CPU-s and was stopped): grep matched nothing and the pipeline exited 0, so a stopped run read as silent. Use `--log FILE` and grep the file, and check heavy's own exit.
- A `_large` held-model property (about 60 CPU-s of its own, more with a cold cache) does not fit the short lane's cap; run it in a hold.
