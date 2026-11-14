# A join on an aspect with purge requests reads every request
> Summary: Granting a role (a join) re-judges each aspect it touches through `retention::purge` `aspect_requests`, which scans every named purge request on the aspect (`pn/` rows): the join's store reads grow with the requests held, against `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6`'s claim that a join with no request does flat work.
> Priority: normal
> Tags: engine, tests

Found by osis-store's `store rows read` counter (catalog gets and scans; added with the sync store): the test's `all_flat("a join")` sees 15 rows at n, 69 at 10n, all of the growth in one scan of `pn/ tid ak` (8 at n, 62 at 10n). The test fails until the join stops reading the aspect's requests (or the claim is restated); it is `#[ignore]`d with this issue as the reason meanwhile.
