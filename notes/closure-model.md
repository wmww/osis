# Closure model
> Summary: The held-model model of the reference graph, the readable closure (held_model::closure, `spec_closure`, the sync differential's oracle): what it checks, P1-P6 with each test, the P5 work counts, and the hole it found in the design: a revocation never reaches a node syncing only the grantee when the target is dependent or the grant is a chain, and with a delete key two honest nodes then undo each other for good; carrying role commits under the thing they name fixes it, and the spec states that rule (spec/permissions.md §4 Role changes travel, spec/sync-judgement.md §2).

Holder access (roles over the world's grants, `Closure::for_keys`, key parts, the path search) is `held_model::closure::keys`: notes/holder-access-study.md, The model. `World::roles_from_reached` is the rule it replaces, kept as the sync differential's oracle until the build.

## The readable-closure model (held_model::closure, tests `spec_closure`)
The model is an oracle written from the design's rules (spec/data-model.md §8, spec/sync-set.md), not from code: plain data, pure functions, 24 tests in about 0.8 s (debug, parallel). Its module doc lists what it leaves out (validity, disputes, key rotation, the wire, sealing, `@` signals, purge, storage rows).

How it reads the plan:
- Strongs are an OR-set of edges per source thing: an add is a commit, a remove names the adds its writer saw.
- A grant is an entry of the target's role record naming a holder, set by a role commit on the target (last wins). "T's keys" (`keys_of`) are the independent things T holds read or above on, by grants followed transitively, a chain giving its lowest role, the best chain counting.
- A sync unit (`sync unit`) walks from T by strongs; a thing T's keys open is in it and followed, any other stops the walk and is not in it (no leaves). Independent things T's keys open are in it.
- `Sync`: nodes exchange per sync ID and log to a store per sync ID. A node syncs each independent thing it holds a ticket or keys for, and every independent thing those sync units hold. It holds only what some sync ID it syncs carries by its own view and drops the rest. A delete-key holder deletes store entries its view does not carry; any node logs what its view carries. Under a sync ID go the commits on its sync unit's things and, as certificates, the role commits on things among its keys.
  - `certify_revokes` also carries a role commit naming a thing among its keys (itself included). That is the fix for the hole below, which the spec states (spec/permissions.md §4 Role changes travel); "by the plan's words" below is the mode without it.
- `closure` walks the node closure sync unit by sync unit. The node's keys and sync secrets are the least sets the independent things it reads yield (a fixpoint over the walk): an open ticket gives its keys only where the walk enters its thing (Interim (issues/tickets-retired.md)), and an independent thing reached that the node's keys hold sync on (no read) is kept unread as by a sync-only ticket. Kept unread, the walk stops at it: the node holds it alone (spec/sync-set.md §2). `Walk::Literal` follows every strong the node can open: a mutation kept for contrast.
- `Net` is release: a pass of a node with its connected peers. `Tree` is the spanning-tree structure for removing a strong.

### Properties and tests
- **P1 Sync units agree.** Every reader of T computes the same sync unit, and reading more changes nothing.
  - `p1_units_agree_exhaustive` covers every world of 2 independent and 3 dependent things, each independent thing holding no role, sync or read on the other, with strongs among 9 candidates. Every member of a sync unit is one T's keys open; readers of T alone and of both compute the same sync unit; toggling a strong inside a thing T's keys cannot open never changes it. PASS.
  - `p1_by_readers_keys_undoes_forever`: walked by the reader's keys instead of T's, a shared store flips every round for good.
  - `p1_carried_commits_decide_the_unit`: 1000 random histories with role commits. A reader holding what T carried after any prefix, plus what it carries after all, computes T's sync unit over all. PASS with `certify_revokes`. FAIL by the plan's words (73 of 16000 readers): a revocation is carried under no sync ID the reader holds, so the earlier grant stands. This is the Hole.
- **P2 Carrying settles.**
  - `p2_carrying_settles_any_order`: 2000 histories, every commit delivered to 3 readers in random order. Every reader ends with the sync unit over all commits; at most 16 adds and deletes over 3 readers and 8 commits. PASS.
  - `p2_per_holder_delete_keeps_concurrent_readd`: node 0 removes A -> P, drops P with nobody connected and deletes P's store entry; node 1 has concurrently re-added A -> P. Node 1's view still holds P, so it logs P again, and both end holding it. PASS. The mutation "gone for everyone" loses P while P is still in the sync unit.
  - `p2_revocation_reaches_grantee_only_node`: the Hole, three cases (dependent, chain, direct). FAIL by the plan's words for dependent and chain; PASS with `certify_revokes`. The direct case passes either way.
  - `p2_sync_settles_random`: 1500 runs in five modes. Each run has 3 independent and 4 dependent things, 3 nodes (plus a fourth reading everything, or none), random delete keys, and 20 steps of writes, grants and revocations, exchanges and store visits, then up to 12 full rounds.
    - With `certify_revokes` every run settles: no two honest nodes undo each other. With the fourth node every node also agrees with every sync ID it syncs. PASS.
    - Fixed grants, no bridge: 26 of 300 runs split. Every split traces to a dependent thing's edit missing at a node (check (d)).
    - By the plan's words, 2 of 600 runs never settle or keep a revoked thing.
- **P3 Holding.**
  - `p3_worked_case`: Bob (tickets for X and Y) holds Y. Carol (X only) does not, and holds the same with or without X -> Y. PASS.
  - `p3_strong_never_changes_what_no_ticket_holds_exhaustive` covers every world of 2 independent and 2 dependent things, grants, 5 candidate strongs, root strongs and every ticket combination. A node reads an independent thing only by keys it holds. It stores one unread only inside a sync unit it has a sync-only ticket for. A strong into or out of an independent thing that it has no ticket or keys for, and that no stored sync unit's keys open, never changes what it holds. PASS.
  - `p3_held_is_carried_exhaustive`: everything held is carried by an entered sync unit or the local part. PASS. The literal walk fails it: with X and U open, X -> L -> M, L and M dependents of U, X holding no role on U, it holds M, which nothing carries. Sync unit by sync unit it holds X alone.
  - `p3_making_rule`: "leave it in the node closure" admits a dependent thing minted with admin X and an independent thing whose keys the maker holds. It refuses one of U's dependents referenced only by X, though a held thing references it. PASS.
  - The new checks (a)-(c) and the reach test for (d) are under New checks.
- **P4 Release.**
  - A pass ends once neither side has anything the other's closure wants, or both hold it; then the node drops what its closure does not reach.
  - `p4_release_random`, 1500 histories over 3 nodes. (a) A node drops only what its own held strongs no longer reach. (d) After a pass every connected peer holds whatever of the node's things its closure reaches. PASS. It counts 12 drops fetched again and 117 strongs reading as not held.
  - `p4_concurrent_readd_refetched_from_adder`: a removal racing a re-add makes the holder drop the thing with nobody connected and fetch it again later from the adder. PASS.
  - `p4_last_reference_gone_is_released`: the last holder drops a thing nothing references. PASS.
  - `p4_strong_to_never_fetched_holds_nothing` is stated behaviour, checked exhaustively up to 4 events on 2 nodes and one thing. No history of 3 events leaves a dangling strong. At 4: node 0 makes X; node 1 writes a strong to X; node 0 removes its strong and, with nobody connected, drops X at once. Node 1 never got X, so its strong holds nothing. Otherwise the strong is written after the drop.
- **P5 Removing a strong cheaply.**
  - `p5_tree_matches_reach_random`: 400 runs of 80 edits on 7 things, cycles and self-strongs included. The structure equals from-scratch reachability after every edit and stays a spanning tree; an unreached cycle goes whole. PASS.
  - `p5_subtree_drop_needs_reattaching`: without the re-attach step, root -> v -> d plus root -> d loses d when root -> v goes.
  - `p5_work_counts`: the counts below.
- **P6 Ephemeral strongs.**
  - `p6_ephemeral_release_random`: P4 (a) and (d) hold with ephemeral strongs and restarts.
  - `p6_restart_drops_only_without_a_peer`: a thing held only by an ephemeral strong survives a restart while a connected peer holds the value. With nobody connected it is dropped and fetched back once the peer is met. It is released everywhere once every holder of the value has restarted. PASS.

Each rule the passing tests rely on was removed once and failed tests:
- walking by T's keys (P1)
- per-holder deletes (P2)
- `certify_revokes` (P1, P2)
- the sync unit-by-sync unit walk (P3)
- serving the peer's wants in a pass (P4 (d))
- re-attaching (P5)

### New checks
- **(a) Nested sharing**, `p3_nested_sharing`. Setup: Y is independent, X is granted read on Y, X -> Y -> B.
  - Y and B are in X's sync unit. A reader of X holds and reads them with no ticket for Y; a node keeping X unread holds X alone (it reads none of X's strongs), their commits carried under X's sync ID.
  - In `Sync`, a node reading only X gets Y's commits under X and syncs Y.
  - Without the grant only a holder of Y's ticket holds Y. PASS.
- **(b) Taking Y out again**, `p3_unlinking_takes_it_out_for_every_reader`. Removing X -> Y, or Z -> A for a dependent A in two sync units, takes the thing out for every reader. Each reader drops it, the delete-key holder deletes its entries, nothing logs them again, and everything settles. PASS under both rules: the removal is a commit on the referrer, which stays in the sync unit.
  - Revoking the grant: FAIL by the plan's words when the target is dependent or the grant is a chain (Hole); PASS with `certify_revokes`.
- **(c) Chains**, `p3_grant_chains`. X opens Y through W by the lowest role along the chain, and the best chain counts:
  - read+read, write+read, admin+admin, and sync direct beside read+write all open Y.
  - sync+admin and read+sync do not.
  - W is among X's keys but in X's sync unit only by a strong. PASS.
  - Chains also run through the random tests and the chain case of the Hole.
- **(d) A dependent thing in two sync units**, `p2_two_units_reach_only_through_a_bridge` and the fixed-grant mode of `p2_sync_settles_random`. The limit is exactly "through a node that syncs both". It reaches by that node's exchanges or through the two stores alone. Every other split traces to such an edit. An independent thing in two sync units has no such limit, since every holder syncs its own sync ID.
  - Two things reach the grantee's readers only through a node syncing both: a grant itself (its certificate must be logged under the grantee by someone holding the target's role record) and, by the plan's words, never a revocation (Hole).

### Hole
**A revocation never reaches a node syncing only the grantee**, for a dependent target or a chained grant.
- Smallest history: Z is granted read on T; A is one of T's dependents; Z -> A. Node 0 syncs T and Z and holds Z's delete key. Node 1 syncs Z only and holds A under Z.
- Node 0 revokes Z's read on T. By node 0's view, A left Z's sync unit. The revocation is a commit on T, which no sync ID node 1 syncs carries, so node 1 never gets it. Node 1 keeps A and logs it under Z again each time node 0 deletes it. That goes on for good.
- The chain form: X has read on W, W has read on Y, X -> Y, and X's read on W is revoked.
- A direct grant on an independent Y settles only because node 1 syncs Y while it holds Y and gets the revocation there.
- Fix (modelled, `certify_revokes`): a role commit naming a holder travels under the sync ID of that holder and of every thing whose keys reach it. With it every random run settles and P1 holds. The spec states it: spec/permissions.md §4 Role changes travel and spec/sync-judgement.md §2 (required set), the role records of a chain's middle things included, applied before the deletes it causes (spec/sync-judgement.md §3 Role entries first).

### P5 counts
Work is edges examined plus parent-chain steps, at n = 50 / 500. `ancestor_step` tries the target's other referrers first, each by walking its parent chain. Without it, a removed tree edge always marks the target's subtree.

| edit | with ancestor step | subtree only |
|---|---|---|
| remove a non-tree referrer of a target with fan-in n | 1 / 1 | 1 / 1 |
| remove that target's tree edge (other referrers outside) | 4 / 4 | 2 / 2 |
| remove a tree edge whose target's other referrers are its own children, one outside | 154 / 1504 | 252 / 2502 |
| remove a tree edge with a shallow alternative, subtree of n | 4 / 4 | 152 / 1502 |
| remove a tree edge whose alternative is n deep, no subtree | 53 / 503 | 2 / 2 |
| release a subtree of n | 101 / 1001 | 101 / 1001 |
| add a strong reaching a subtree of n | 51 / 501 | 51 / 501 |
| add a strong to a held thing | 1 | 1 |

- Fan-in alone does not grow the cost.
- Each variant grows with the wrong thing in one shape: the ancestor step with the depth of the alternative, subtree marking with the size of the subtree kept.
- Running both searches in lockstep, stopping at the first answer, costs at most twice the smaller and meets both rows (not modelled).
- Both grow with fan-in when the other referrers sit below the target, as any search that must rule them out does.
- Nothing simpler meets the counts: a reference count releases no cycle, and a from-scratch walk at each pass end costs the held set per pass.

### Questions for the design
1. The Hole: stated as the model's rule (spec/permissions.md §4 Role changes travel).
2. That rule keeps a revoked entry of a role record carried under the former grantee. How long? Settled: `ROLE_KEEP` after replaced, a removal after its `ts` (spec/sync-judgement.md §2); the model keeps it for good.
3. A direct revocation on an independent Y reaches X's holders through Y's own sync ID. That needs them to keep fetching under Y after the removal and the key change, until they hold the removal. Spec/sync-opens.md must allow it.
4. Where a chain's middle record travels. The model carries the role records of every thing among a sync ID's keys as certificates, W included though it is not in X's sync unit; the spec says so (spec/permissions.md §4 Role changes travel).
5. What a read of a strong that holds nothing returns (P4): "destroyed", "released" and "not held" read alike, with no marker (spec/sync-set.md §2).
6. A node-root strong to a dependent thing in no sync unit the node syncs holds it only where the node made it: nothing carries it there otherwise. This is the P4 rule again, not a new case.
