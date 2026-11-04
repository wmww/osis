# held-model: spec ambiguities
> Summary: Every place the spec left a choice, contradicted itself or said too little while building held-model, with the sentence cited and the choice the model makes. Most important first.

Each entry: the spec text, the problem, the model's choice (and where in the code).

## Headline

1. **An invalid delta's hidden anchors and keep at most.** spec/commits.md §5: "A write of a delta invalid here does not die ... But under keep at most 0 after replaced ... each counts dead from its **fall**"; spec/crdt.md §4.6: "Seq elements created by an invalid delta keep their record and creation write (anchor) as a content-less hidden anchor"; §5 live write: "including element records the state keeps only as anchors". Nothing says whether those hidden anchors make the invalid body *live*. If not, the body drops at its fall with no carrier and others' valid inserts anchored on it vanish (the model's drop property found this; test `invalid_text_body_dropped_at_its_fall_keeps_its_anchors_spec_commits_5`). Choice: they are live writes, so the drop needs a carrier and the anchors stay in the state (`model.rs`, deaths loop, `crdt::holds`).

2. **Keep-at-most deadline contradicts itself.** spec/commits.md §5: "A node drops a body no earlier than its bound ... and no later than the bound plus `AT_MOST_GRACE` after it first saw the body dead" vs "By the bound every node MUST drop the body". Also "first saw the body dead" is arrival history, not a function of the held set. Choice: `MayDrop` from the bound, `MustDrop` from bound + `AT_MOST_GRACE`, measured from the bound itself.

3. **Re-grant revives everything since the first grant.** spec/permissions.md §5.2: "An actor holding the required role in the timeline's final state ... is re-granted: each of its writes ordered at or after the first point it held that role is valid again, including those in the gap." "First point" could be the first ever grant or the start of the current tenure; only the first reading revives "those in the gap". Choice: first ever. Consequence: any later re-grant undoes a demotion's deliberate omissions (spec/permissions.md §3 Lockout recovery, §5.1 Omission on purpose) and a purge-right loss (§7).

4. **A frontier validates writes made without the role.** spec/permissions.md §5.2: "Otherwise it is valid iff the frontier of X's newest valid explicit demotion below write on N lists its commit." This does not require X to have held write when it wrote; a demoter lists every received commit of X (§5.1 Listed), unauthorized ones included. Choice: literal (valid). Likely unintended (`roles.rs`, `valid_as`).

5. **Death dating: first held vs earliest.** spec/commits.md §5: "a superseded write's death at the `ts` of the first superseder the node held, never earlier than the death" (arrival order; and "never earlier than the death" is circular) vs spec/crdt.md §4.8: "the earliest `ts` among the valid writes the node holds that supersede it ... the order of arrival does not matter". Choice: §4.8 (`model.rs`, deaths).

6. **Own state "counts as a snapshot" vs un-merge.** spec/crdt.md §4.6: "The node's own current state counts as a snapshot it holds, so live writes of bodies dropped under keep-at-most survive" and "A valid snapshot's copies of those writes stay". Read together, the own state would keep invalid writes forever. Choice: own-state writes are removed when their own delta is invalid, like a delta body's; only real snapshots vouch (`model.rs`, state building).

7. **Which records are live writes.** spec/commits.md §5: "any write of its deltas the node's state holds by dot, including element records the state keeps only as anchors ... but not an element's or entry's tombstone (it holds the remover's reset, not the creation)". Unclear for (a) a bare anchor whose creation a reset pruned (no write left) and (b) the remover's own surviving reset or removal. Choice: both live. Consequence: a text-insert body always has a live write (never "no live write ... needs no carrier"), and a `remove_aspect` body stays live until a later reset.

8. **"Author lowered" has no ordering.** spec/commits.md §4: a delta counts as held when "the node holds one of the following on the delta's thing ... with a frontier that does not list the delta's commit": no requirement that the role commit be ordered after the delta's commit. An old demotion makes every later missing delta of a since-re-granted author count as held, so its commit applies without it. Choice: literal.

9. **When a leftover may go.** spec/crdt.md §4.7: the leftover is "a held body like any other ... that uploads nowhere"; spec/commits.md §6: "every node holds them value-less, the body ... as its leftover, whatever the delta's keep-at-least bound". Nothing says when an expired or purged delta's leftover is dropped (keep at most? covered?). Choice: a leftover is terminal in the model (`Fate::Leftover` before any bound).

10. **Grace on which bound.** spec/commits.md §5: "the bound is T, or under 0 after replaced the first death, plus `AT_MOST_GRACE` while the body has a live write; with both, the earlier" can add the grace to both; spec/wire.md §1 `AT_MOST_GRACE`: "added to the keep-at-most bound of 0 after replaced (the first death)". Choice: the relative bound only.

## Others

11. **Covered with value-less copies.** spec/commits.md §5 Covered: covering is the canonical-bytes join test, yet the MUST beside it says "(a value-less copy matches)". Under spec/crdt.md §4.1 the valued copy wins the join, so a snapshot holding a value-less copy of a body's valued write fails the test. Choice: the join test decides (not covered).

12. **"Explicit demotion below write" is not defined in §5.1's terms.** spec/permissions.md §5.1 defines demotion as a class fall (owner chain, edge admin, invite); §5.2 uses "explicit demotion of X below write on N". Choice: an applied edge write by another author taking X's role from at least the need to below it (`roles.rs`, `demotions`).

13. **Applied or held purge request.** spec/commits.md §5: "Every node applying it drops"; §5 A waiting part under a purge and §4 Purged: "a held purge request". Choice: an applied request for applied targets; a held, unparked one for waiting parts and atomic apply.

14. **Possible admins from parked commits.** spec/commits.md §4: "by what the node holds of any validity and whatever followed". Parked commits are held but "counted as not received" (spec/crdt.md §2.2). Choice: parked commits give nothing.

15. **Expiry as a death date.** spec/commits.md §5: "an expiry dates none" vs spec/crdt.md §4.8: "It dies at the earliest `ts` ... or at T". Choice: T counts once passed; no effect, since the body is then a leftover.

16. **An un-merged valid write's fall.** spec/commits.md §5: "An un-merged write's fall is at the latest fall on the aspect": every invalid delta on the aspect, ever? Then one new invalid write moves every such fall later. Choice: the latest fall of any invalid applied delta on the aspect, no earlier than the write's own `ts`.

17. **Two rights for a covered drop.** spec/commits.md §5 Between the bounds: "the covering snapshot's own commit holds the right over it, as a purge request would at that snapshot's key"; spec/sync.md §7 adds "it may purge the body" (the node itself, at no stated key). Choice: both; the node's right judged after every held key.

18. **Purging a snapshot by aspect history.** spec/commits.md §5: a request names deltas "by commit, by a whole aspect history, or by author on an aspect"; "A snapshot a request names itself ... its body is dropped". Whether "a whole aspect history" includes snapshot deltas is not said. Choice: yes, judged by the snapshot's retention (`writer`) and its author.

19. **A content commit with no part held.** spec/commits.md §4 Pending: "the node holds no part of it, and a thing of it waits or a delta of it is missing and not counted as held". With every part missing but counted held (expired, purged, under a snapshot), the commit is not pending, so it applies as a header alone, and counts as "another commit with a delta on the aspect" for other parts' keep at most. Choice: as written.

20. **Past keep at most counts any later commit as the first death.** spec/commits.md §4: "the first death taken at the earliest such commit's `ts`": a later commit on a map or text aspect need not supersede anything in the missing delta. Choice: as written (the late live part joins on arrival, §4).

21. **Map presence after an entry expires.** spec/crdt.md §4.3 counts "its children's writes", so another delta's write inside an entry whose creation expired keeps the map present: it reads `{}`, not absent (test `expired_key_copy_in_another_body_is_stripped_spec_commits_6`). Choice: as written. (The writer MUST have given that write the same expiry, spec/crdt.md §4.7, but a receiver cannot rely on it.)

22. **Stripped copies asked for again.** spec/permissions.md §7: "A held body stripped for carrying a purged value is asked for again with any such fall". While asked for, does the stripped copy still join? Choice: yes, value-less (it only hides).

23. **An invalid snapshot's copies' deaths.** spec/commits.md §5: "A write of a delta invalid here does not die". For an invalid snapshot carrying copies of valid writes that do die, the model treats its writes as not dying (fall under 0 after replaced).
