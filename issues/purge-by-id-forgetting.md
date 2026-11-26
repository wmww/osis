# purge_by_id reads differ forgetting or not on some seeds
> Summary: osis-engine `retention::tests_carried::purge_by_id_reads_alike_forgotten_or_not_plain_spec_commits_5` fails on main at seed 679952827408 (step 8: node 0 reads x:b.0 as Some(Int(5)) forgetting, None not); seed 0 and most seeds pass. Cause not studied. Separately, its coverage floor fails at 8 seeds from 347698118767 (`purges through a name: 0 over 8 seeds, under the floor 2`): no seed of that run purges through a name; at 8 seeds from 532945376426 it counts 1.
> Priority: normal
> Tags: retention, tests

Replay: `OSIS_PURGE_BY_ID_START=679952827408 OSIS_PURGE_BY_ID_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact retention::tests_carried::purge_by_id_reads_alike_forgotten_or_not_plain_spec_commits_5`. Listed in tools/known_failures.txt (rate). Fix with a hand-written reproducer (notes/principles.md, Never pin a seed).

The floor failure: `OSIS_PURGE_BY_ID_START=347698118767 cargo test -p osis-engine --lib -- --ignored --exact retention::tests_carried::purge_by_id_reads_alike_forgotten_or_not_plain_spec_commits_5`. A count floor at the gate's 8 seeds depends on the offset; the generator should make a purge through a name in every seed it means to cover, or the floor should count what every seed does.

The floor also fails at 8 seeds from 532945376426 (`purges through a name: 1 over 8 seeds`).
