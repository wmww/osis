# keel-current-setting
- Two `cargo build`s raced when a foreground build moved to the background on timeout and I started another; the second waited on the first's lock. Long engine links (~8 min) make the 120 s foreground timeout a trap: start engine builds in the background from the first.
- Splicing a long test file with marker-to-marker python replacements: an end marker far down silently swallowed four tests. Cut by line numbers after `grep -n` instead.
