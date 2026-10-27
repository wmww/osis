# Deaths still depend on order once a superseding body is dropped
> Summary: The deaths replay (`retention::rejudge_deaths`) cannot see the writes of dropped bodies that left the state, so after such a drop a replay can date a write's death later than the in-order join did; nodes holding the same commits then keep different bounds (always later, never earlier, than spec/crdt.md §4.8).
> Tags: retention, node

Repro: `cargo test --workspace --test it retention::deaths_alike_after_superseder_dropped -- --ignored`. X < W < Y on a kept register, W under keep at most 0: Y kills W and drops its body. In order, X died at W. A lagging writer's V (older than X) arriving afterwards replays the aspect without W, so X dies at Y.

Same mechanism, uniform retention: a keep-at-least set, element e added by X, removed by W; a compaction drops W's body (live, no dead write: past its bound) while X's stays to W + D; a concurrent remove Y (offline writer, `ts` before the snapshot) kills W's reset in the state. A node that replays after the drop dates X at Y, one that judged X while holding W at W. Also: two snapshots carrying one write of a dropped commit, the later taken after the write died, record it dead again at a later winner (pushes `last` late).

Effect: every recorded death is the `ts` of an applied superseder, so a replay's deaths are never earlier than the spec's; the late node holds longer. Keep at least: it judges the body must-hold after another node deleted it at the server and re-uploads it for up to Y − W. Keep at most: it keeps erased data past the bound by up to Y − W.

Fix direction: the replay needs each dropped superseder's stamp. Per-write death records (a write is not identified by its stamp: path identities needed), or a small per-aspect record of the stamps of dropped bodies' writes kept until every body they could date is gone.
