# A from-now grantee counts a pre-cut rotation's body missing forever
> Summary: in siblings::a_from_now_grantee_after_a_removal_holds_the_old_readers_roster, node 3 (granted t with History::None after a rotation) holds that rotation commit (keys.0, sync.0, secrets.0 on the account) with an entry it opens, yet `read_facts(S, c).missing` stays true at quiet: its body under S lists parts it can never get.
> Priority: normal
> Tags: sync, engine

`bodies_under(.., unheld: true)` adds missing parts to the body; a part node 3 cannot open (likely the secrets.0 section under an epoch below its floor) then counts missing for good. Its judgement stays "missing": nothing is fetched (it has the only entry) and it never logs the body (§2 Loggable: may-hold), so no loop, but the body never counts held and status/judgement read a state that cannot end.

Expected: a part the node may not read (below its floor, spec/crypto.md §4 State at a cut) is no part of its body under S, so the body counts held. The harness check `World::unreached_must_holds` skips the missing-parts test for held bodies until this is fixed; once it is, check that a held body under S at a caught-up reader is not missing.
