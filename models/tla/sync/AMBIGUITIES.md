# Sync convergence model: ambiguities and findings
> Summary: Places where spec/sync.md §5–§7 and spec/commits.md §5 left a choice or failed a checked property. S1–S10 are resolved by spec edits and the model follows the new text; S11–S15 are open (S11 is a TLC counterexample, `mostabs_serve.cfg`).

## Resolved (model updated, rerun clean)
- **S1. A purge compacted away never reached a late node.** commits §5: a commit carrying a purge request MUST NOT carry `expires` and its blobs are kept at least until `wall_ms(ts) + MEMBERSHIP_KEEP`, whatever its deltas' bounds. `purge_reach.cfg` now passes `PurgeReachesAll` (within MEMBERSHIP_KEEP; see S15).
- **S2. Absolute keep-at-most stranded live writes.** commits §5: live writes stay in the node's state after the drop; a body with live writes is deleted at a label only while another entry carries them; snapshot deltas take the schema's default bounds, never a commit's. sync §7: a right holder that must delete such a body and finds no carrier uploads a covering snapshot first. `mostabs.cfg` passes `NoLiveLoss`, `LiveKept`, `Clean` (but see S11).
- **S3. Must-hold and must-not-hold overlap.** sync §6: "A body meeting a must-not-hold condition is must-not-hold whatever else holds of it."
- **S4. Strict subset against a superset that is itself must-not-hold.** Text unchanged (literal). The window in which a node that has not applied a purge re-uploads the purged body closes once it gets the purge commit, which commits §5 now keeps MEMBERSHIP_KEEP; `purge.cfg` passes `Clean` and `Quiesce`.
- **S5. Which deletions wait.** sync §7: carriers are a covering snapshot, a blob of the commit holding a superset of the deltas, or an identical body.
- **S6. What a reader relays.** sync §6: "the stamped must-hold entries it holds that the label lacks".
- **S7. "Dropping them once".** sync §6: once per body (commit and delta set).
- **S8. Header-only rewrite.** commits §5: a node dropping a body for a purge keeps the commit as a blob without the purged deltas, header-only when none remain. Model: any node does so (was: writers only).
- **S9. Coverage of a body with no delta.** commits §5: "A body holding no delta is covered."
- **S10. Who must snapshot.** sync §7 (snapshot before deleting a body with live writes that nothing carries) and commits §5 (re-snapshot after a purge). The model makes only these snapshot writes fair; `mostabs.cfg` and `purge.cfg` pass `Clean` with compaction unfair.

## S11. A body past its absolute keep-at-most before it reaches the label (TLC: `mostabs_serve.cfg`, Serves fails)
- Text: commits §5 "Keep at most: by the bound ... every node MUST drop the body; its live writes stay in the node's state"; sync §7 the snapshot-first rule fires only for "a right holder that must delete a body with live writes"; "a member serves current state from the bodies and snapshots it holds".
- Trace (4 states): w1 writes c5 (keep at most absolute T = 1), time passes T before w1 uploads (offline, or simply slow), w1 drops the body. The label never had it, so nobody must delete it and no rule asks for a snapshot. The live write sits only in w1's state: w1 holds no body or snapshot for it, and no other member ever gets it, unless someone compacts by choice.
- Checked: if the body is uploaded before T, `Serves` holds.
- Options: (a) the snapshot-first rule also covers a node that must drop a body with live writes that no entry under the label carries; (b) a writer uploads (or snapshots) before the bound and treats an absolute keep-at-most it cannot meet as expiry.

## S12. Carrier checks race (not modeled)
- Text: sync §7 "deleted at a label only while another entry under it carries them ... an identical body (one of two duplicates goes without waiting)".
- The server is blind and cannot check carriers; each right holder checks its own view. Two right holders with stale views can each delete one of two identical must-not-hold bodies (or a body and the superset carrying it), leaving no carrier. The model updates every view atomically on delete, so it cannot show this.
- Option: an identical body counts as a carrier only for the higher blob ID (the duplicate rule's order), so two deleters agree which one stays.

## S13. Timed deletes of bodies with live writes (not exercised)
- Text: commits §5 "At most D after replaced: the replacing node sends blind nodes a delete timed at the bound"; the bound is first death plus D; sync §7 carrier rule.
- A body with several deltas can still have live writes at first death plus D. The server deletes it unattended, so the carrier rule cannot hold unless the sender ensured a carrier when sending. The scenarios only time-delete single-delta bodies.
- Option: send the timed delete only for a body whose writes all die by the bound, or upload a covering snapshot with the timed delete.

## S14. A header-only rewrite is never must-hold
- Text: commits §5 the purge rewrite is "held and uploaded like any body", and "A body holding no delta is covered".
- Covered means may-hold once past keep-at-least, so nobody uploads a header-only rewrite and a compactor may drop it at once: the header the purge kept need not reach the label. Model: literal. Harmless for convergence; matters only if headers are meant to persist.

## S15. A node offline longer than MEMBERSHIP_KEEP never applies a purge (not checked)
- Text: commits §5 purge commits kept MEMBERSHIP_KEEP, then compactable like any body.
- After compaction a returning node holding the purged body sees it covered by the snapshot (may-hold) and keeps the purged value. Same horizon as membership compaction; the model keeps time below the bound. Option: record as an accepted limit, or let a snapshot carry the purge requests of the commits it covers.
