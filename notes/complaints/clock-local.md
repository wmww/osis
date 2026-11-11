# clock-local
> Summary: the issue's part (1) had already landed; "corrected" vs "raw" time ran through ~30 node files as two clocks that were one.

- The issue still described the own-commit drift check as `h.author != me`; main already skipped `Origin::Local` (an earlier merge). Read the code before trusting an issue's "Today".
- Removing the correction left `raw_now` and `now` reading the same clock in node-sync; merging them touched every timer and comment. A sed with line ranges was safer than a global rename (`raw` is also "raw records").
- Node test `Net` had one clock for all nodes: tests skewed nodes through `set_clock_offset`. It now has `Net::set_skew`; sim net scenarios skew clocks ±20 s, which the correction used to hide (the ephemeral cursor check assumed seconds apart).
