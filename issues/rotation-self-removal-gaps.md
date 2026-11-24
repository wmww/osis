# Self-removal rules no rotation test catches
> Summary: Two self-removal rules survive their plants over every rotation lib test; each needs a small test that fails without it, or the rule shown redundant and removed.
> Priority: low
> Tags: tests, engine

- `pins` (core/keys/src/covers.rs): a departs mark names a tail write only while the mark's author holds `r` (`held.holds(&w.key.node, r)`). Planted away: no `rotation::` engine lib test fails, `tests_departs::self_removal_uncovered` (the leaver's own mark and own rotation) included. Either another rule already keeps a leaver's mark from covering its own departure (then the clause is dead) or no test reaches a mark by an author who no longer holds the role.
- `self_removal` (engine/src/apply/validity.rs): planted to never hold (`author == holder` false and the admin-through-holder branch false), several `rotation::tests`/`tests_members` tests fail, but not `tests_departs::a_mint_admins_removal_of_its_holder_is_a_self_removal` (a holder's mint admin, or an account's node, removing it through the holder alone): its removals apply by another route, so the test does not show the spec/permissions.md §2 rule it names.
