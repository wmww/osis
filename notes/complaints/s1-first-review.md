# s1-first-review
- Review: why the made-here clause was needed took a traced diff of two runs; blob IDs differ per run, so the diff had to go by commit IDs and engine rows (`World::rows` for the thing, `why_kept`). The cause was an older engine order dependence (issues/lost-part-read-again.md), not the delay.
- Review: an env-var probe switch with an empty value (`X= cmd`) still counts as set for `std::env::var(..).is_err()`; a "baseline" run that way was the probe.
