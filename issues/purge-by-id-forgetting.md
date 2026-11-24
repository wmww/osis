# purge_by_id reads differ forgetting or not on some seeds
> Summary: osis-engine `retention::tests_carried::purge_by_id_reads_alike_forgotten_or_not_plain_spec_commits_5` fails on main at seed 679952827408 (step 8: node 0 reads x:b.0 as Some(Int(5)) forgetting, None not); seed 0 and most seeds pass. Cause not studied.
> Priority: normal
> Tags: retention, tests

Found by the gate of spar-fork-rotation (touches no retention code), replayed on main's binary: `OSIS_PURGE_BY_ID_START=679952827408 OSIS_PURGE_BY_ID_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact retention::tests_carried::purge_by_id_reads_alike_forgotten_or_not_plain_spec_commits_5`. Listed in tools/known_failures.txt (rate). Fix with a hand-written reproducer (notes/principles.md, Never pin a seed).
