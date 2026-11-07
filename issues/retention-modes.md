# Retention: three history modes
> Summary: Replace keep bounds with a per-write history mode (convenient | kept | none) beside purgeable-by and expiry (Tess). Every drop that is not expiry or purge is a right holder's covering compaction snapshot; a node without write drops nothing on its own but expired content. Death dating, carriers, carrier-only, keep bounds and their timers, keep-bound never-received, `Why::Flip`, dropped-snapshot liveness and crdt §4.6 "own state counts as a body" go. Decided (Tess): the history value is either `none` (gone once replaced) or keep-at-least-until T for T in [0, ∞]: 0 is convenient (no promise), ∞ kept forever, a finite T keeps and exposes the write's history until T (a duration is fixed into T at write time from the write's own `ts`). Expiry is the separate purge-at-T. Readers under none drop when a writer's covering snapshot arrives; none compacts at every replace; expiring deltas are kept to their T; `nobody` needs T = ∞; the purge floor stays.
> Priority: normal
> Tags: engine, spec, retention

## Model
- **convenient** (default): no promise, not in `history()`; a right holder compacts whenever it likes; its valid covering snapshot drops the body everywhere.
- **keep-at-least** (Tess, revised): until an absolute T and/or until D after replaced (T = ∞ forever). Enforced only as a limit on writers' compaction and on what `history()` shows; readers date nothing. "Replaced" is the earliest valid replacing write the compactor holds, by that write's signed `ts`; compactors may judge differently (each snapshot vouches); a replacing write that later turns invalid is the accepted compaction limit. `history()` shows an entry while the node holds no replacing write stamped more than D ago (and before T): a function of the held set, so nodes holding the same data show the same; nodes holding different replacements may differ, like any read. Earlier form, kept for reference: **keep until T** (T > now): must-hold and never compacted before T; leaves early only by purge or expiry; exposed by `history()` until T (H3, issues/history-verified-or-absent.md); after T it is convenient. T comes from the write (absolute, or `ts` + a duration fixed at write time), so every node judges it alike up to `MAX_DRIFT`; `history()` hides entries within `MAX_DRIFT` of T. T = ∞ is kept forever. `nobody` requires T = ∞.
- **none** (`writer` only): every writer holding the body that applies a write killing any write of it writes a covering compaction snapshot in that transaction; the body drops as covered everywhere.
- **Expiry** unchanged (content lifetime, unattended at every node). An expiring delta is never covered, so it is kept until T whatever its mode. **Purge** unchanged; the purge floor (ROLE_KEEP after the request) stays. ROLE_KEEP for keys/secrets/label becomes compactor policy.

## Uses
core.osis role aspects → convenient (+ROLE_KEEP policy); `created.0`, `required.0^` → kept (fixed); `purge.0` → convenient; notes `note:pinned.0` → none; chat messages → kept or expiry (chat `EditMode::Keep` needs kept); sim `s:latest.0` → none; absolute keep-at-most T (tests only) → goes; relative keep-at-least other than ROLE_KEEP: tests only.

## Survives of the R × D class
A cover that turns invalid (Uncovered repair, as today); a valid snapshot written after a kill that later turns invalid keeps the kill's copy (the stated Permissions limit, now at every none replace); expiry-pending and purge falls.

## Plan (each step gates)
0. Model: held-model history modes; state == join of held bodies, alike reads, no writer holds an uncovered none body with a dead write after its transaction, kept never dropped but by purge/expiry; TLA sync: no timed deletes, delete only covered. Run against today's engine.
1. Wire/schema/API: `Retention { by, history }`, `required.0^`, schema syntax `[by: writer, history: none]`, refusals; delete absolute keep-at-most, keep-at-least bounds, carrier-only; tests and vectors.
2. none = compaction on replace; remove reader drops, timers, `judge_at_most`, `date_falls`, `Dropped::live`, keep-bound never-received, `Why::Flip`, timed deletes, oracle carve-outs.
3. Death dating out (deaths.rs etc.); liveness stays.
4. crdt §4.6 own-state clause out; `check_rebuilt` exact.
5. H3 history API.
Requirements text (Tess): Deletion modes; "by the bound every node MUST drop" → writer compacts at replace, others drop as the snapshot arrives, a node without write acts alone only for expiry; Deterministic limit shrinks; Scale exception: every replacing edit; History line.

## Fallback for none (Tess)
If `none` as compaction-on-replace causes problems: `none` becomes `writer` purgeable plus the writer attaching a purge request for the replaced writes to each edit of such an aspect (generated automatically). Known costs from an earlier look (notes/engine-retention.md, writer-side purge): a purge cannot express a partial replacement of a body, a purge request is kept to its floor (ROLE_KEEP), and purged writes leave leftovers. Acceptable as a fallback ("a little more jank").

## Names (Tess)
"No history needed" is the default, never the delete-on-change option. The API and schema names carry this, not a doc line: the default is unnamed (no retention attribute: history not promised, not exposed, kept while convenient); keep-at-least is named for keeping (e.g. `keep_history: until T / for D after replaced / forever`); the delete-on-change mode is named for what it does, e.g. `purge_on_replace`, and documented as rarely the right choice because it costs more per change (public docs never mention compaction). `keep_history` until a past time or for 0 is the same as the default. Internal names (`none` above) follow the public ones when built.

## Readers under keep-for-D (decided, Tess)
One rule for every node: a body under keep-for-D is not dropped until D after the earliest valid replacing write the node holds (a function of the held set, not arrival order). Readers and writers holding the same data then show the same history.

## Small values (Tess)
Per-commit overhead matters less than extra mechanisms. Do: forget compacted headers when nothing needs them (growth row 1). Maybe: a whole replacement covering the old body directly, only if cheap. Don't: special commit forms for small durable writes.
