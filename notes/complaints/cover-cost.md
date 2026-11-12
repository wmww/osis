# cover-cost
- A background test run whose log went to a scratchpad subdirectory not yet made failed at once with exit 0 shown by the wrapper (the `echo` ran): check the log exists before trusting a quick "done".
- Wire pages are content-defined at about 64 KiB, so a "flat" read at positions still costs a whole wire page per body; a scale test needs entries fat enough for several pages at small n, else the small size is one page and shows nothing.
