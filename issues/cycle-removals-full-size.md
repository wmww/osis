# The cycle harness fails 4-5% of seeds at full size, leaks included
> Summary: osis-engine `rotation::tests_members::cycle_removals_leak_nothing_random_large` passes at its plain size (1000..1020) but fails 46 of 1000 seeds from 1000 (its own full default range 1000..1200 has 1032, 1034, 1036, 1044, 1055, 1132, 1169, 1181, 1189), 43 of 1000 from 9540000 and 51 of 1000 from 5000000, on depth0 before and after its squash. Main's version of the harness: 0 of 1000 from 1000. Every leak is a two-admin seed with hidden grants, though every grant is synced before the removal.
> Tags: security, keys, engine, tests

Repro: `OSIS_CYCLE_START=1032 OSIS_CYCLE_SEEDS=1 cargo test -p osis-engine --lib rotation::tests_members::cycle_removals_leak_nothing_random_large -- --ignored --exact` (0.2 s).

Kinds over 1000..2000:
- 21 "after the removal": the removed party D opens the newest read epoch of up to three actors after `leaks_after_cascade` (every actor's admin ran `ensure_rotated` to quiet). All have `two` admins and `hidden` (grants made without syncing between them); `common` and `by_d` both ways; k 3 or 4. The harness runs `sync_all` after the grants and before the removal, so every node holds every grant. Under rule 4b (taint) the leak should stop once the writer holds the grants and the cycle's commits (issues/keys-depth0.md), so this is past the stated limit unless the oracle counts something the limit allows.
- 25 "every holder with key access re-sealed" (liveness after `settle`): all `two` admins without `common`, hidden or not.
- 5 harness `Permission` unwraps (seeds 9540070, 5000054 among them): a grant or demotion the harness expects to be allowed is refused.

Next: replay 1032 (D self-removes, write role, k 3, no common admin) and find which epoch D opens and through which box; check whether the knowing re-key after the hidden grants ran before the removal.
