# read judges a body again after each delivery
> Summary: A node settles every module after each input, and read's `judged` re-runs a body's judgement each time one of its reads moved, so a run to quiet judges each (node, S, commit) several times, a fifth to a third of them giving the answer already held. Narrow each judgement's reads to what decides the body; a prune's stamp checks also run over every absent-row reader of its table.
> Priority: normal
> Tags: sync, performance, tests

Work per round is flat in history (`growth::flat_work`). The re-runs that change nothing come from reads that move under the answer; the commonest, by a probe of each judgement's moved reads: `timelines: into` (roles at now through `held::Timelines::role_now` stamp every holder's `Into` read), the peer record index scans (a prefix read per source), own entry rows (`E/`, `X/`) read whole where the judgement uses a field, heads (a head move judges each body under S twice by design: notes/sync-read.md). Reads under `index: commits` are on purpose: whether an entry strips reads each part its blob carries (`blob_gone`, `strips`), and a fresh encryption reads every held part (`may_log`).

Direction: per cause, narrow the read to what decides the body (fast by construction); never settle less often (batching would hide the cost from tests, not remove it). A count of no-change re-runs per key at quiet would guard it, beside `growth::flat_work`.

A prune of a store table's removal stamps (`memo::Table::prune`) moves no `Effects` reader of another absent row, but `Effects::due` checks each such reader's stamps once per prune: O(absent-row readers) per prune. Bounding removal stamps by the readers too (a prune per as many removals as there are readers at bucket stamps) makes it O(1) per removal.

Tried and not landed: narrowing `role_now` to (node, thing) stamps written per edge change (nodes reaching the holder × things the target reaches) saved about 1% of osis-sync `it` but stamps grow with the whole role relation (147 stamps for one grant at 5 members × 20 things, 10,452 at 50 × 200; kept for good): rejected by fast by construction. The shape that would hold: stamp only pairs someone read (per thing, the nodes whose `role_now` on it was read; an edge change intersects them with the nodes reaching the holder). Low priority beside its gain.
