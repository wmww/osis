# Retention: three history modes
> Summary: Replace keep bounds with a per-write history mode (convenient | kept | none) beside purgeable-by and expiry (Tess). Every drop that is not expiry or purge is a right holder's covering compaction snapshot; a node without write drops nothing on its own but expired content. Death dating, carriers, carrier-only, keep bounds and their timers, keep-bound never-received, `Why::Flip`, dropped-snapshot liveness and crdt §4.6 "own state counts as a body" go. Decisions pending with Tess: readers under none; snapshot at every replace; expiring kept to T; nobody needs kept; the kept window.
> Tags: engine, spec, retention, tess-call

## Model
- **convenient** (default): no promise, not in `history()`; a right holder compacts whenever it likes; its valid covering snapshot drops the body everywhere.
- **kept**: must-hold, never compacted; leaves by purge or expiry; exposed by `history()` (H3, issues/history-verified-or-absent.md). Optional window (Tess, pending): kept for edits stamped in the last D or since T, by the edit's own signed `ts` (no death dating); older entries unexposed and compactable; the window edge is fuzzy by `MAX_DRIFT`. `nobody` requires kept.
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
