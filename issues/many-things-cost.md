# What a node holding many things still pays per write
> Summary: Whole-set values kept per read thing or per sync ID still cost O(things) per make: `certificate_records(s)` (read's `cert_blobs` effect) filters a read thing's every certified record at each change; the n-th made thing's apply, validity rejudge and timelines updates are unmeasured for growth. Linear but heavy: a 2000-thing commit costs about 23 M instructions per thing (debug).
> Priority: normal
> Tags: engine, sync, performance

Measured with `tools/icount` and `tools/cpuprof` on osis `it` (debug). What one thing stores, downloads and signs, and the changes left for it: notes/thing-cost.md.

- **Certificate records per sync ID.** `Engine::certificate_records(s)` (osis-sync read's `cert_blobs` effect per (S, records), via `cert_blobs_missing`) folds `records_of(t)` per read thing: every record its certificates name, filtered by `ctx.holds` and `reads`. The account root's records grow with every plain thing made under it, so each make re-runs O(things): about 7% of `tracking::dispatch_counts_matched_listeners_at_n_and_10n`. Follow it per record as `sync::listed` follows carriers (`Certified::namers` already gives the read things naming each record), with the effect reading the records not carried per key.
- **Still to count at n and 10n held things** (each shows a few % of that test, growth unknown): `apply::validity::rejudge_all`/`misjudged`, `Timelines::update_touched`, `rotation::members::keyless_in`.
- **Per thing of a big commit** (`commits::changes_on_as_many_things_spec_requirements_decentralization`, linear: 5.2 G at 200 things, 54 G at 2000 before the certified rows): `CommitSecrets::key` → `Core::own_epochs` → `ActorEpochs::derived` per thing, `write::framing_for`, `Core::delete_base`, `follow_certificates` (a `Piece::Chain` per thing, each naming the account's commits).
