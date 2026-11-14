# spec-anchors-rest complaints
> Summary: Footguns met fixing the remaining stray test anchors.

- `citations()` read `notes/x.md §3 (y)` as a section of the comment's spec file, so note sections showed up as stray spec anchors; fixed (notes/ paths are skipped like RFCs).
- Anchors written as prose summaries wrap across comment lines, so rewriting them by hand or sed misses the wrapped ones; a regex joining words with `\s+(//[/!]?\s*)?` catches them.
- claudewait cannot wait on Agent IDs; waiting on forks needs a Monitor on their output files.
