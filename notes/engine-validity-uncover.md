# Engine: uncovering
> Summary: How a body dropped as covered goes missing again once its covers no longer carry it (`retention::uncover`, spec/permissions.md §5.2): the test, when it runs, the chain of covers, fetching it back.

## The test
A body dropped as covered (`Dropped::as_cover`) stays dropped while the test that dropped it (`snapshot::covered`) passes on what is held now; bodies dropped by expiry or purge stay dropped. It passes with:
- **a carrying snapshot**: a coverer held with its body and valid, or itself dropped as covered under covers that carry it (`retention::coverers` walks the chain);
- **or two own replaces**: any two valid held own replaces later than the body (`snapshot::own_covers`), recorded as its covers or not, so the test is a function of what is held. With one, a node deletes at other nodes what a holder judges uncovered and logs again (`one_own_replace_left_covers_nothing_spec_commits_5`); with only those it dropped under, it goes missing where a holder judges it covered (`any_two_held_own_replaces_keep_a_drop_spec_commits_5`).

## When it runs
Whenever a cover on the aspect may stop carrying: it turns invalid, arrives again judged invalid, or drops or goes missing other than as covered (`drop_part_for`, `unstrip`). A part failing the test is set missing, and the aspect rebuilt and flagged suspect (`Why::Uncovered`). It joins as a late part when it arrives again.
- A missing snapshot covers nothing until it arrives (`covered` → `None`): else any older valid snapshot would "cover" it and the compactor drop it for good.
- A missing part dropped later (a purge) is no longer missing (`drop_part`).
- Chains un-drop whole: a delta dropped under S1 and S1 under S2 both go missing when S2 falls; the delta's writes come back from S1's copies once S1 is fetched again.

## The chain of covers
- Only the chain records a cover. With the body gone, nothing else tells a snapshot carrying it from one that does not: tables reach no expiring delta and no delta whose writes died unseen (spec/crdt.md §8), and `covered` on a dropped body is too loose to keep writes by.
- So a forgotten coverer hands its covers down (`apply::unindex::hand_down`, via `Indexes::covered_under`): each part naming it names what it dropped under instead, O(those parts) per forget. Else a coverer forgotten before a body dropped under it breaks the chain, and every `uncover` fetches, flags and drops the body again (`forgotten_coverer_hands_down_its_covers_*`, `forgotten_coverers_keep_the_chain_short_*`).
- The chain is sound only because `covered` judges a held body by the join alone, not the frontier: a snapshot can carry writes past its own frontier (its writer held the body behind a session gap). By the frontier, a holder would call uncovered what a node that dropped the body calls covered, and re-place it every pass for the other to delete (`held_memory_body_past_a_snapshot_frontier_judged_by_the_join_*`).

## Fetching it back
- The body counts missing again (`facts.missing`), so read fetches it where a source shows it (spec/sync-judgement.md §3 Dropped bodies; `Streams::fetch_again` is not built: issues/sync-unbuilt.md). A holder finds the body uncovered, so must-hold, and logs it again (`coverer_demoted_after_cover_drop_alike_*`, `covered_drop_coverer_and_remover_revoked_alike_*`).
- Limit (spec/permissions.md §5.2): with no copy anywhere the write is gone at every node alike. Usually only a reader holds it then.
- The order harness drops covered bodies at every sync step (`order.rs` `drop_covered`) and checks a reopen reads alike, so open-equals-rebuild covers un-drops.
