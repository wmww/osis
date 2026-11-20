# A vouch for a role write is defeated by the party it holds out
> Summary: A removal or demotion X made that the remover never received is kept only by a witness's vouch, and the lowered party's key defeats the witness by a backdated lowering of it: the removed party ends admin, no dispute shown. No rule over the held set tells that world from its honest mirror. The proposal (witnesses make the write again as their own, no vouch for role writes) is modelled in roles-model `paths` as `Rules::remake`; notes/role-remake-model.md has both rule sets' results and the questions for Tess.
> Priority: normal
> Tags: perm, security, tess-call

**Worlds** (roles-model `src/paths/tests.rs`): `the_pair_under_the_vouch_reads_the_thiefs_side_unshown` (today's rule: the thief's side, unshown, where the removal is trusted), `the_pair_under_remake_is_an_ordinary_fight_shown_to_both_worlds` (the proposal: a dispute either world's user sides on).

**The story's gates** with the witness-lowering moves (`MOVES` 53 to 60, `Setup::n5` 4) fail under both rule sets: notes/role-remake-model.md, Results. The properties `random_worlds_hold_large`, `small_family_holds_large` (today's rule) and `remake_random_worlds_hold_large`, `remake_small_family_holds_large` are KNOWN failures (tools/known_failures.txt) until the decision.

**Waiting on Tess**: notes/role-remake-model.md, For Tess.
