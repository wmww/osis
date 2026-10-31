# eph-cost-bounds review
- My first repro test passed on the old code: a cap below the blob's size refuses it at the node cap, before the share check is ever reached. Pick a cap between the blob's size and four times it, and assert the blob size in the test.
