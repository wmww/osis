# history-links
- `tools/mutate.py` with an OLD that ends in a call followed by `?` at the site (`count_earlier(..)?`) does not build: the planted `if` cannot infer the `?`'s error type. Plant on a NEW like `Ok::<(), crate::error::Error>(())`, or pick a site whose value is plain.
- The "depth room" gap needs a hostile delta (the writer refuses deep values before chunking); no engine test helper builds a delta with a link placed deeper than it was made for, so it went to an issue.
