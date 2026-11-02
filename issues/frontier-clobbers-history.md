# A demotion's frontier may leave out history a snapshot does not keep
> Summary: Clobbering fixed by frontier-study F2 (a demoter leaves out only what its own compaction could drop now, `receipt::droppable_here`). Left: under keep-at-least forever the frontier now lists every kept write, so a kick scales with history there until permanent heads (notes/frontier-study.md F3/F4) are built.
> Tags: security, spec, permissions, engine

Owner: incorrect, and especially wrong for a thing set so admins cannot erase history. Candidate rule: a frontier may leave out only a commit whose body its retention lets be dropped now (past keep at least, right holder); keep-forever writes are always listed. Then the frontier is O(surviving writes) forever for such aspects: see the hash chain idea in e-review.md and the size limit (8 MiB, about 2.5x10^5 commits).

Related limit to decide: the frontier is the demoter's own word, so a hostile admin can list nothing and make every write of the demoted member invalid, under any retention. Bodies stay must-hold (`must_hold` does not read validity) and a re-grant revives them, but state and any validity-filtered read lose them. So "admin cannot erase history" holds for bodies, not for validity. Is that acceptable, and should a history read show such writes as disputed instead of absent? Requirements Permissions (edits the revoker had not received are lost until re-grant) accepts the honest case.

Owner requirement: the cost of a kick, in general and not only for chat, must not scale with history size. So the fix cannot be a frontier that lists every surviving write.

Purge rights are sets now (osis-base `PurgeBy`): a demoter may drop a body only per `Timeline::may_purge`, and an admin holds no right under `author` unless it acts for the header's actor (`Header::purge_actor`). Old `author` is `author_or_admin`, same code 2; `author` is the new author-only class, code 4. Nothing about permanence changes.

Study: notes/frontier-study.md: permanent deltas (keep forever, no keep-at-most, no expiry; headers never dropped, purge residues included) get one head per (aspect, device) with per-session predecessor links in the author's own headers; everything else lists IDs, leaving out exactly what the demoter's compaction would drop now. Kick cost: one entry per permanent aspect plus the compaction tail. Hostile-admin limit accepted as out of scope.

F2 (built): a superseded write inside its keep-at-least window is listed (`validity::frontier_keeps_superseded_kept_write_spec_perm_5_1`). What stays open is the cost side for permanent aspects (F3/F4).

Also listed for as long as their header is held (review of F2): a commit with any missing delta (`receipt::part_missing`: on a thing the demoter does not hold, or, since R1, a part dropped at its expiry or keep-at-most bound, even off the aspects in question), and a part dropped other than as covered (expiry, keep at most). So mixed commits touching an unheld thing or an expiring aspect, and every expired write, still make a kick scale with history. Headers are never forgotten yet (session-sources rule 8), so the frontier walk itself visits every held header of the demoted node on the aspects in question, as on main.
