# harness-clock
- order.rs is 4.5k lines; reading the harness core (play, oracle, alike, check_orders) took most of the model time. Output of `sed -n` over it hits the tool's size cap: read with Read and offsets.
- A test passing prints nothing captured: `OSIS_ORDER_STATS` lines need `--nocapture`, which notes/testing.md does not say.
- Copying the test binary for background oracle runs (coordination.md) was needed: I edited sources while they ran; `cp` onto the copy then failed with "Text file busy" until the run ended.
- Load ~20 made per-branch oracle costs 3-4x notes/testing.md's figures (alike_large 735 CPU-s with the clock off vs 187 documented), so cost comparisons need an on/off env knob (`OSIS_ORDER_CLOCK=0`) on the same load.
- Review: `--nocapture` stats lines run past 400 chars; cutting them with `cut` hid the register-deaths counts on the alike run. Print stats on their own lines.
