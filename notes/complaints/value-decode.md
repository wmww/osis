# value-decode
> Summary: workflow notes from the value-decode branch.
- A VmHWM child test passes falsely (0 B per byte) if the test built the input as `Value`s first: freed heap is reused by the decode. Build hostile inputs as raw bytes.
- `LabelStore::put` returns refusals as `Ok(Code)`: a test that `.unwrap()`s a deposit over the budget goes on silently with no entry. Assert the code.
- Review: `[a, b].concat()` on the shape lists cloned them; freed clones made VmHWM read 10 B per byte low. Move, don't clone, before a peak.
- Review: VmPeak in a test thread steps by 64 MiB (malloc arena), so a claim limit needs that slack.
