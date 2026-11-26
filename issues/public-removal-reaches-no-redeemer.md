# A public link's redeemer misses the public's removal
> Summary: a node reading a thing by the public alone (a public link redeemed) keeps reading after the public's read is removed: it never receives the removal commit, though its readers hold the notice (spec/sync-opens.md §6, A reader tells a public reader the public's removal). Fails on main at world seeds 1-5 of the script below.
> Priority: normal
> Tags: sync, security, tests

Script (osis-sync differential harness, default size): `New(0), Give(0, 0, Public, Reads), Run, Redeem(1, 0), Run, Revoke(0, 0, Public)`. At quiet node 1 still reads thing 0 at the public's last epoch (n 3), holding neither the removal (its rotation, n 4) nor the step after it; nodes 0 and 2 each hold one notice of the removal under thing 0's sync ID (`Engine::notice_rows`), yet node 1 is served neither notice nor removal. By world seed (`holds_on(seed, ..)`), node 1 still reads at seeds 1, 2, 3, 4, 5 on a95a240ee and at 0, 2, 5 on spar-key-records (commit bytes moved: grants write no `keys.0`). The test `differential::a_public_links_redeemer_loses_the_thing_with_the_public_spec_permissions_3` passed at seed 0 by chance; it is ignored, naming this issue, until fixed.

Spec: spec/sync-opens.md §6: a member opened on the public entry, the public's read since removed, is ended with `until` the highest position of an entry of the public's edge on S's thing, so the redeemer holds the removal when it next meets a reader. Look at where a public-entry member is judged ended (the public's removal held at the source) and whether its `until` covers the removal's entry; the notice path (spec/permissions.md §4 Notices) is for departed members, which the public's reader may not be.

Next: a hand reproducer at a constructed world (not a seed), then the fix; un-ignore the test.
