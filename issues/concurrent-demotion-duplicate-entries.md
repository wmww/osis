# Concurrent demotions by two admins: duplicate entries deleted
> Summary: two admins of t demoting the same writer at once (each rotating) leave two duplicate entries under a label, deleted again (`sent_kinds[14] == 2`), the shape the re-registration fix closed for one fresh rotation; the re-send after a refusal under an older head has no test now.
> Priority: low
> Tags: node, sync, tests

Reproducer (fails on main and on rotation-churn): in osis-node
`deletion::reregistration_waits_and_sends_once_spec_sync_5`, replace the scenario by: g =
group(a, [(b, Read), (c, Read)]); t = item(a, g, g); run; a grants c admin and b write on t; run;
clear `sent_kinds` and `uploaded`; `demote(a, t, b, Read)`; `demote(c, t, b, Read)`; run. The
"no duplicate entries to delete" assertion fails (2), the "refusal went again under the new
head" one holds.

That test's own scenario (a grant, then at once a demotion with no rotation) made c's uploads
refused and sent again under t's next head only while t rotated seven times; with g's rotator
rotating t at once (`rotation::rotate_above`) nothing is refused, so the refusal path lost its
check. This scenario restores it once the duplicates are fixed. Rotation count in it:
issues/concurrent-lowerings-merge-twice.md.
