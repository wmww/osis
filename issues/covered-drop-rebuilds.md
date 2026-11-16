# A compaction's covered drops each rebuild the aspect
> Summary: every body dropped as covered runs `apply::rebuild` of its aspect (shredding the state), so a compaction dropping k bodies of an aspect of size n costs O(k·n); with the geometric trigger k grows with n, so an aspect written once per thing (the account root's `holds.0`, `tickets.0`) costs O(n) per write amortized. Skipping the rebuild breaks the shred rule.
> Priority: normal
> Tags: engine, performance

Found making things at n and 10n (osis `making::`): the bytes streamed at a compacting make grow with the aspect (`rebuilt < rebuild < drop_part_for < drop_body`, once per dropped body).

Rejected: returning early for a whole body dropped as covered with nothing uncovered. The state's value is the same, but `shred::erasing_edit_drops_replaced_body_unrecoverable_spec_commits_5`, `shred::purged_on_replace_paged_unrecoverable_spec_commits_5` and `scale::purge_on_replace_pays_its_state` fail: the rebuild is what rewrites the stored state shredded, so the dropped body's bytes leave freed pages (spec/commits.md §5).

Directions: drop a compaction's covered bodies in one transaction with one rebuild per aspect; or rewrite shredded only the pages that held the dropped body's writes (notes/local-store.md, the paged design's O(pages holding the body)).

Remaining cost after the making fix (osis `it`, tools/icount): `tracking::dispatch_counts_matched_listeners_at_n_and_10n` at 40 and 400 things 38 G instructions (5 G before the making rule), `commits::changes_on_as_many_things_spec_requirements_decentralization` 96 G (8 G before). Not yet attributed; this rebuild per covered drop of the account root's `holds.0` is the first suspect.
