# Roster moves in `changed_at`: no product scenario needs it
> Summary: opens' credential digest carries S's roster (`opens/holds.rs` `c.roles = rc.roster`, spec/sync-opens.md §3 `changed_at`, §6 re-judging), yet with that line removed no osis-sync test fails but the scripted opens tests that model it; every roster change that matters in the product comes with a credential change at one end. Keep J re-judged on the roster (the spec's plain rule, NetOpen.tla ON_jnow/ON_endj) or delete it and weaken the spec.
> Priority: low
> Tags: sync, tests

With the line removed, the whole osis-sync `it` binary passes; with the scripted harness's `judge_as` also not moving `roles`, five scripted tests fail (`opens::j_is_judged_on_the_roster_held_now`, `a_j_open_closes_at_a_removal`, `a_close_for_a_departure_keeps_nothing_here`, `a_kept_stop_goes_with_its_connection`, `a_rejoin_reads_from_the_losts_cursor`): they check spec §4/§6 as written, through a fake.

Why no product scenario was found:
- A grant (no rotation): the grantee takes it and its credentials change, so its own test Hits or sends ByRole.
- A removal or demotion below read carries its rotation in the same commit (spec/permissions.md §3), so read secrets change.
- A departure without a rotation (a self-removal, a removal by an author that may not rotate) is a role commit logged under S itself: the departed nodes get it on that very member and stop S; and nobody encrypts under the uncovered epoch until a rotation, which moves credentials.

Deleting it means: drop "a role on S changes, or an actor reaching S changes" from §3 `changed_at` and "roster" from §6's re-judge triggers, rewrite those five tests to move credentials as the product does, update NetOpen.tla, and remove `ReadCredentials::roster` from the engine facade (only opens reads it). The cost is a weaker statement of J ("judged on the roster held now", re-judged only when credentials move).
