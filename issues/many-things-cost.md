# What a node holding many things still pays per write
> Summary: osis `it` tests that make hundreds or thousands of things grow faster than linear: making the n-th plain thing costs about 51 M instructions at 100 things and 87 M at 400 (debug); `commits::changes_on_as_many_things_spec_requirements_decentralization` takes 96 G, 40% of it `Engine::may_log` → `wrap_under` → `opened::header_passes` → `Core::secret_actor` per content part of a 2000-part commit, under memo stamp recording. Not yet fixed.
> Priority: normal
> Tags: engine, sync, performance

Measured with `tools/icount` and `tools/cpuprof` on osis `it` (debug):

- `commits::changes_on_as_many_things_spec_requirements_decentralization` (2000 things in 4 commits of 500, then one commit on all 2000): 96 G. 40% inclusive is read's `judge::body` → `Engine::may_log` → `section_secret` → `wrap_under` → `passes_on_parts` → `sync_ids::opened::header_passes`, which asks `Core::secret_actor` (a record-chain walk) for every content part of the commit, with each step recorded into the running memo frame (`Stamps::record`, about 16%). The judgment is re-run as what it read moves, so a 2000-part commit pays parts × re-runs.
- `tracking::dispatch_counts_matched_listeners_at_n_and_10n` (40 and 400 things): 30 G. Per made thing the growth is in cover judgments reading the account root's `holds.0` snapshot whole (`snapshot::covered_read` via `held_part_at`, about 10%: below the paging size a snapshot part is one piece), the compaction trigger's weighing (`Engine::compactions`, 8%) and `body_facts`.

Look first at `header_passes`: one judgment per part where one per commit (or per thing's secret actor, a memo) would do.
