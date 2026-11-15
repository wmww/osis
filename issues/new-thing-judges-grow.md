# A new thing listed in home re-judges in proportion to the things before it
> Summary: osis `scale::a_new_thing_judges_the_bodies_it_changes` (test-opt-11) fails once create no longer files: a thing listed in home by the test's own `group.0` write judges about 100 bodies after 10 things and about 630 after 100 (flat under create's filing). Ignored until fixed.
> Priority: normal
> Tags: engine, sync, tests

Seen when test-opt-11 landed on undo-create-home: the test was written when `create` listed the thing as a subgroup of D in its creating commit; it now lists it with `w.group(db.home()).add(Subgroup(t))` in the same commit. Per new thing writing no compaction snapshot: after 10 things {2, 74, 92, 110} judgements, after 100 {2, 622, 652}. Find what that write moves that create's filing did not (the account chain's `Indexes::role_on` reads, or the listing writing as another author), make it flat, and un-ignore the test.
