# Sync convergence model: ambiguities and findings
> Summary: Places where spec/sync.md §5–§7 and spec/commits.md §5 left a choice or failed a checked property, with the assumption the model made. S1 and S2 are TLC counterexamples.

## S1. A purge compacted away never reaches a node that syncs later (TLC: `purge_reach.cfg`, PurgeReachesAll fails)
- Text: commits §5 "Every node applying it drops ... every body carrying their values"; sync §6 may-hold includes "covered"; sync §7 compaction drops "the bodies they cover that it may purge and whose keep-at-least bound has passed"; a purge request is a header field of an ordinary commit with ordinary retention.
- Trace (about 15 states): w1 writes c3 = {a, b} and uploads it; w2 downloads it, writes p (resets a, purges a), drops c3 and keeps the rewrite {b}, re-snapshots (s covers a, b and p's reset), uploads s, deletes the old c3 blob at the server, then compacts p and the rewrite (both covered by s, no keep-at-least). w1 downloads s, never sees p, and keeps c3 = {a, b} with a's value for ever: to w1 the body is covered by s, so it is may-hold and nothing makes it drop it.
- The same holds for a node offline across the purge and the compaction, and for a peer that relays the old body later (it is covered for everyone, so nobody deletes it as must-not-hold except nodes that applied p).
- Options: (a) a commit carrying a purge request gets a fixed keep-at-least (e.g. `MEMBERSHIP_KEEP`, like membership deltas); (b) a compaction snapshot carries the purge requests of the commits it covers (so applying the snapshot applies them); (c) a commit carrying a purge request is never covered (S9), so it stays must-hold. (b) closes it without a time bound; (c) is the smallest text change but keeps every purge commit for ever.

## S2. Absolute keep-at-most on a live write contradicts "a member MUST always be able to serve current state" (TLC: `mostabs.cfg`, MemberCanServe fails; Clean fails too)
- Text: commits §5 "Keep at most: by the bound ... every node MUST drop the body; its live writes stay in the node's state. A body with live writes is deleted at a label only once a snapshot covering it is under that label"; "Absolute T: right holders delete at blind nodes when next online after T"; "Compaction-snapshot deltas are `writer` with the aspect's bounds"; sync §7 "a member MUST always be able to serve current state, from bodies or a snapshot".
- Trace: w1 writes c5 (keep at most absolute T = 1) and uploads it; r downloads it; at T both drop the body. Neither holds a body or snapshot for the live write: nobody can serve it. A snapshot cannot help: it carries the same absolute bound. At the server the entry is must-not-hold but has live writes and no covering snapshot can ever be under the label, so it is never deleted (Clean fails): the server keeps exactly the body every node was required to drop.
- Options: (a) an absolute keep-at-most also kills the writes at T (it becomes a second expiry, then drop is safe); (b) allow absolute keep-at-most only together with an expiry no later than it; (c) let the snapshot of the aspect not inherit the absolute bound (then keep-at-most of the original body is satisfied by compaction). (a) or (b) match the evident intent.

## S3. Must-hold and must-not-hold overlap (assumed: must-not wins)
- Text: sync §6 defines must-hold ("before its keep-at-least bound or established uncovered") and must-not-hold ("purged, expired, past keep-at-most, outside the required set, or a blob of commit C whose delta set is a strict subset ...") as if disjoint; commits §5 says only "Where the two bounds disagree, keep at most wins".
- They overlap: purged or strict subset while uncovered; past keep-at-most while uncovered (S2); expired before keep-at-least (commits §6 says expiry wins). Model: must-not-hold wins every overlap; deletion at the server still waits for a covering snapshot when the body has live writes.

## S4. Strict-subset rule against a superset that is itself must-not-hold (assumed literal)
- Text: sync §6 must-not-hold "a blob of commit C whose delta set is a strict subset of another held blob of C under that label".
- A node that has not applied a purge holds the old full blob, so it classifies the purge rewrite as must-not-hold, deletes it at the server (once a snapshot covers it) and re-uploads the old blob, purged value included, as a fresh encryption if tombstoned. TLC shows this resolves once the node gets the purge (purge.cfg passes Quiesce and Clean), but in the window the purged value goes back to the server; with S1 the node never gets the purge. Model: literal (the other blob need only be held). Option: the superset must not itself be must-not-hold, and a purge rewrite is recognisable from its header (it names nothing new, but the purge commit is separate; the rewrite could carry the purging commit ID).

## S5. Does "deleted at a label only once a snapshot covering it is under that label" apply to duplicates and strict subsets? (assumed: not to duplicates, yes to strict subsets)
- Text: sync §7 "The same order, snapshot under the label first, applies to every deletion of a body with live writes"; "Two blobs of one commit with the same delta set under one label: a token holder deletes the one with the higher blob ID".
- Deleting one of two identical bodies, or a subset of a held superset, leaves the live writes under the label. Read literally, both wait for a snapshot. Model: duplicates exempt, strict subsets wait. Spec should say which.

## S6. What a reader relays (assumed: must-hold only)
- Text: sync §6 "a reader relays the stamped entries it holds"; "Nobody acts on may-hold bodies except a compactor dropping them once".
- Model: a non-writer relays only entries that are must-hold for it and the label lacks.

## S7. "dropping them once" (assumed: once per body per node)
- Text: sync §6 "Nobody acts on may-hold bodies except a compactor dropping them once (§7)".
- Once per body (commit and delta set) or per blob ID? A re-uploaded fresh encryption has a new ID. Model: once per body per node.

## S8. Header-only rewrite vs "a dead class is deleted rather than rewritten" (assumed: rewritten)
- Text: commits §5 "Purging drops bodies, never headers. A commit with a purged delta is rewritten as a blob without that delta"; sync §3 "a dead class is deleted rather than rewritten".
- When every delta of a body is purged (a projection of one purged delta), is it rewritten as a header-only blob or deleted? Model: a header-only rewrite (empty delta set), which is then vacuously covered and compactable. Who writes the rewrite is also unstated; model: every writer that drops a purged body (copies are duplicates resolved by §7).

## S9. Coverage of a body with no delta on the aspect (assumed: vacuously covered)
- Text: commits §5 "A body is covered by a snapshot the node holds when joining each of its deltas into the snapshot's fragment of that aspect leaves its canonical bytes unchanged".
- A header-only rewrite, or a commit whose deltas are on other aspects, is vacuously covered by any snapshot. Model: vacuously covered. Together with S1 this is what lets the purge commit go.

## S10. Who must snapshot (assumed: someone, fairly)
- Text: sync §7 "a node that may write an aspect uploads snapshot commits"; commits §5 "A body with live writes is deleted at a label only once a snapshot covering it is under that label"; commits §5 purge: "A writer that ... holds no covering snapshot ... re-snapshots there".
- Except after a purge, no rule obliges anyone to snapshot, so a must-not-hold body with live writes (keep-at-most, strict subset) can stay at the server indefinitely. Model: snapshot writes are weakly fair (someone eventually does). Spec could say that a right holder that must delete a body with live writes and finds no covering snapshot under the label writes one.
