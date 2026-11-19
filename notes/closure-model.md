# Closure model
> Summary: Two held-model models of the reference graph. The unit model (held_model::unit, `spec_unit`): the sync unit as one independent thing and the dependents it reaches, with blobs per target named only as the design allows, entry through entered units, one walk and key paths; readings, controls, properties with world counts, the chain-exceeds-oracle count, and five open findings against notes/sync-unit-design.md (a keeper misses what only a reader names; the blob set depends on history; an unjudgeable forgery stays; key paths miss a chain the referrer lacks; key paths loop under forks). The readable-closure model (held_model::closure, `spec_closure`, the sync differential's oracle until B2): what it checks, P1-P6 with each test, the P5 work counts, and the hole it found in the design: a revocation never reaches a node syncing only the grantee when the target is dependent or the grant is a chain, and with a delete key two honest nodes then undo each other for good; carrying role commits under the thing they name fixes it, and the spec states that rule (spec/permissions.md §4 Role changes travel, spec/sync-judgement.md §2).

## The unit model (held_model::unit, tests `spec_unit`)
The decided unit (notes/sync-unit-scope.md; notes/sync-unit-design.md §2-§4, §6), beside the readable-closure model below, which the sync differential reads until B2. Plain data, pure functions, 18 default tests in about 3 s (debug, parallel) and one ignored twin (`p2_keeper_enters_what_a_reader_enters_family_full`, 3 s under `tools/heavy`).

Readings (the simplest where the notes leave a choice):
- **Unit by reach** (`Unit::Reach`): H and the dependents of H (mint-admin chain first meeting an independent at H) reached from H by strongs whose sources are in the unit. A dependent outside it is in no unit: carried nowhere, its strongs list nothing. A node entering a unit holds it whole.
- Grants are between independent things; every grant is sync or read. H's step lists H and every thing with a direct grant on H. A role commit on H naming W travels under S(H) and S(W) with H's boxes to W (Bootstrap): a node reading W holds H's read secret when W holds read on H. Steps are current.
- **A blob per target** (`Member::Target`): S(G) requires one blob per thing outside G's unit that a live strong of G's unit targets, naming the target's independent's unit; no role is read.
- **Can name** (`View::can_name`), the only way a writer or reader knows a target's unit: it reads the target's unit (for a dependent target, the target in it: its record chain is there), or the target is independent and it reads a unit whose independent holds a direct grant on it (Bootstrap).
- **Blob rules at a store** (`Net::look`): rule 1, any writer deletes a blob whose tag no live strong of the unit targets; rule 2, of blobs for one tag naming the same unit, one naming every path of another and more wins, equal ones keep the lower ID; rule 3, a writer that can name the target deletes one naming the wrong unit, and one that holds the grants of a path (reads the holder's or the target's unit) deletes a blob whose path does not stand. A writer logs its own blob for a target it can name unless a blob it keeps covers it. Writers also log the body entries of their view of each unit and delete those outside it.
- **The walk** (`walk`), one function for readers and nodes keeping units unread: a unit named by a blob of a followed unit is entered while a unit the node entered (or a root) is on its step; read where a unit it reads holds a direct read grant on it; least fixpoint. A reader also names the targets of units it reads by its own `can_name` (design §3). No secret reaches a unit the node has not entered.
- **Key paths** (`Paths::Via`): a blob carries every chain of holders from G to the target's unit whose grants the logger sees, where G holds no direct grant on it; path units are entered for keys (their secrets, read where possible) and not followed.
- **Who wrote a static world's blobs** (`listing`): `Writers::Full`, a writer of every unit seeing every grant; `Writers::Own`, S(G)'s only writer a reader of G alone walking its own closure.

Controls (the earlier readings and the rules' removals): `Unit::All` (every dependent ever minted in the unit), `Unit::Held` (also every dependent of H a strong the node holds targets from another unit), `Member::Role` (targets cut to those G holds sync on by any chain; smallest split: 0 holds sync on 1, 1 on 2, 0 -> 2, where 1's grant does not travel under S(0); as a keeper's list it is also "only what the referrer can itself enter", which in 0 reads 1 and 2, 0 -> 1 -> 2 cuts 2 off), `Enter::Deep` (sync secrets through grants at any depth, units on the way unentered), `Enter::Free` (entering with no secret), `follow_unread: false` (today's keeper, stopping at a unit kept unread), `Paths::Followed` (path units followed as members), `Net::delete_unnamed` (deleting blobs for targets the writer cannot name), `Net::lowest_wins` off, `Net::deletes` off, and `pass` with a count of referrers.

Properties (family: independent 0, 1, 2, dependents 3 of 1 and 4 of 2, every grant among 0, 1, 2 of none, sync or read, every set of 8 candidate strongs, 186624 worlds; random: 600 worlds of 4 independent and 4 dependent things):
- **P1 one unit, one target list** (`p1_readers_compute_one_unit_and_one_target_list`): every reader of G computes the same unit and targets whatever else it reads. Design: 0 failing (family and random). `Unit::Held` fails the unit in 58320 worlds (random 424; the targets 204 random); `Member::Role` fails the targets in 59072 (random 142).
- **Release** (`unit_by_reach_releases_a_dependent_and_what_only_it_listed`): H -> X -> K; removing H -> X takes X's entries out of S(H), its blob for K out, and K out of the keeper. `Unit::All` keeps both for good; `Unit::Held` never settles (two writers of S(H), one holding a strong into X, log and delete X).
- **P3 release by reachability** (`p3_detached_cycle_is_released`): a detached cycle goes whole; the referrer count keeps it.
- **P4 converging** (`p4_attach_detach_every_order_converges`, `p4_random_histories_settle`): three scenarios, 720 schedules each, with a writer of every unit and a writer of S(0) alone (which cannot name a dependent target): every end state lists exactly the targets some writer can name, once, right unit, right bodies, keeper on its walk, quiet. 400 random histories, two writers syncing random units: all settle, none wrong. `delete_unnamed` undoes the namer for good; with `lowest_wins` off two writers' simultaneous blobs both stay.
- **Role ops write no blob** (`role_ops_write_no_member_blob_but_first_names`): over 300 random settled histories one grant set, changed or removed: no delete or rewrite of a standing blob; 5 first blobs logged for targets the grant made nameable (Bootstrap). `Member::Role`: 204 blob operations or no settling.
- **P2 keeper = reader, P2b reads by the closure** (`p2_keeper_enters_what_a_reader_enters_family`, `_random`): with `Writers::Full`, the keeper of 0 enters exactly the units the reader of 0 enters, the reader reads exactly those 0 holds read on through chains whose holders are units it entered, and every unit entered is on such a chain: 0 failing (family, random). With `Writers::Own`: P2 fails 1512 (random 3), Finding A; P2b 0. Keeper controls (P2 against the design's reader, `Writers::Full`): `Member::Role` 432, `follow_unread: false` 114048, `Enter::Free` 47628; `Enter::Deep` enters a unit through a holder outside the closure in 11016.
- **Chain exceeds the oracle** (the count issues/unit-key-paths.md asks about): worlds where 0's role over any chain on a unit its closure references exceeds its role through closure units: 18738 of 186624 (random 44 of 600); with `Writers::Own` 21024. Smallest: 0 reads 1, 1 reads 2, 0 -> 2 (`p2_a_unit_reached_through_a_holder_outside_the_closure`): 2 is not entered at all; `Enter::Deep` kept it unread.
- **A strong to a dependent brings its unit** (`p2_strong_to_a_dependent_brings_its_unit`), where the dependent's unit reaches it; see Finding B where it does not.
- **Key paths** (`key_path_followed_and_dropped_with_its_grant`): logged with the path by a writer seeing both grants, the keeper enters W for keys and H by W's secret, the reader reads H; the path grant removed, the writer deletes the blob and logs it without the path, the keeper drops W and H. Over the family with `Writers::Full`: P2 and P2b by the closure 0 failing; P2b against 0's role over any chain fails 17012 (30996 without paths; random 55 and 82), Finding D. `Paths::Followed` holds more units (W's own members, in the test; 0 extra in the family, 1 in random).
- **Work at a change** (`work_at_a_change_counts`, 0 referencing holder 1 and n members granted to 1, n = 5 and 50): a detach 1 blob delete; a grant on a member 0; the root's grant on the holder removed 0 (the keeper drops every unit but its root, none of which it can enter any more: the release, in proportion to what goes); `Member::Role` n deletes there. Rotation is not modelled (no epochs).
- **P5 hostile writer** (`p5_hostile_member_blobs`): a forged blob for an untargeted thing goes at the next honest visit of any writer (rule 1); one naming the wrong unit for a live target is left by a writer that cannot name the target and set right by one that can (rule 3); a keeper enters a forged unit only where a unit it entered is on that unit's step. 300 random hostile histories, writers syncing random units: all settle, none wrong except 27 ending with a blob no honest writer judges (Finding C). `deletes` off: 157 keep a forgery.

### Findings (open)
- **Finding A: a node keeping a closure unread misses what only a reader names.** World: 0 reads 1 and 2, 0 -> 1 -> 2 (`p2_keeper_misses_what_no_writer_of_the_referrer_can_name`). S(1) requires a blob for 2; a writer of 1 can name 2 only by reading 2 or 0. The reader of 0 reads 1 and names 2 itself (0's grant on 2 travels under S(0)), and enters it by 0's secret; the keeper of 0 enters 2 only by S(1)'s blob. With S(1)'s writers reading 1 alone nobody logs it (P2 fails so in 1512 family worlds), so the keeper keeps {0, 1} for good and a fresh reader it serves never gets 2. It goes where the reader of 0 writes 1, or any writer of 1 reads 0 or 2 (including the author of 1 -> 2 when it held 2's name). Against notes/sync-unit-design.md §3 ("one walk" for readers and keepers; "Why a referrer's own role is not asked" assumes S(H) lists K) and spec/requirements.md Data model ("a thing takes with it the part of its closure it can itself sync"), for keepers.
- **Finding B: the blob set depends on history.** A blob logged by a writer that could name its target stays when no writer can any more, since rule 3 judges only by a writer that can name (`a_blob_named_by_bootstrap_outlives_the_grant`: 0 references 1 and 2, holds sync on 1, 1 holds sync on 2, S(0)'s writer reads 0 alone; 0's grant on 2 given and removed leaves the blob, and the keeper of 0 enters 2 by 1's secret; never given, it does not). The dependent form pins issues/unit-dependent-release.md's cost (`pin_a_strong_to_a_dependent_its_unit_dropped`: 0 reads 1, X a dependent of 1 that 1 stops reaching, 0 -> X): X is held by nobody and the strong is carried with no target in both orders, but S(0) lists 1's unit, and keepers and readers of 0 enter it, only if the blob was logged while 1 reached X. Against §6's "a strong from outside to a dependent thing brings its independent's unit, always" and P4's stated end state; random histories rarely reach it (0 of 400).
- **Finding C: a forgery no honest writer can judge stays for good**: one for a live target no writer of the unit can name, or any in a unit no honest writer visits (27 of 300 hostile runs). A keeper enters such a unit only by a secret it holds, as for any forgery. Against §3's "the next honest writer deletes it by rule 1 or 3".
- **Finding D: key paths do not reach 0's role over any chain** (`key_paths_miss_a_chain_the_referrer_does_not_hold`): a direct sync grant hides a read chain (0 holds sync on 2 and read on 1, 1 read on 2, 0 -> 2: no path is logged, 2 is kept unread); and the chain is the root's, not the referrer's (0 reads 1 and 3, 3 reads 2, 0 -> 1 -> 2: S(1)'s blob has no path, 2's step lists 3, which nothing names). Against issues/unit-key-paths.md rule 2's "keeps the requirement under either reading".
- **Finding E: key paths under forked sides** (`key_path_under_forked_sides_never_settles`): two writers holding different role records for a path grant for good log and delete the path blob without end; spec/sync-judgement.md §4 (once per change of ground, not modelled) bounds it, leaving whichever acted last. Without key paths a fork over grants changes no blob (no promotion here).

### For promotion (brief 2)
- Kinds are per `View` (`View::of` takes them), so a promotion is an `Op` flipping one kind to `Independent`; `in_unit` then moves X and the dependents it reaches. Commit bodies already have per-unit entries (`Net::bodies`), so moving them by entries, the carrier rule before deleting from S(H) and the late writer go there.
- `can_name` needs the promotion's rule: a promoted X named by a reader of H (S(H) keeps X's `created.0`, `sync.0` and P while the record edge stands). Rule 3 then makes a writer holding P log X's own unit and delete the blob naming H; Finding B says a blob naming H stays where no writer can name X.
- Forked promotions: `Blob.unit` becomes a set of units, rule 2's covering already orders such blobs; neither side's keeper may lose the unit its side names.
- Still out: a promotion judged invalid (kinds flipping back), a mixed commit, validity and disputes generally.

## The readable-closure model (held_model::closure, tests `spec_closure`)
The model is an oracle written from the design's rules (spec/data-model.md §8, spec/sync-set.md), not from code: plain data, pure functions, 24 tests in about 0.8 s (debug, parallel). Its module doc lists what it leaves out (validity, disputes, key rotation, the wire, sealing, `@` signals, purge, storage rows).

How it reads the plan:
- Strongs are an OR-set of edges per source thing: an add is a commit, a remove names the adds its writer saw.
- A grant is an entry of the target's role record naming a holder, set by a role commit on the target (last wins). "T's keys" (`keys_of`) are the independent things T holds read or above on, by grants followed transitively, a chain giving its lowest role, the best chain counting.
- A sync unit (`sync unit`) walks from T by strongs; a thing T's keys open is in it and followed, any other stops the walk and is not in it (no leaves). Independent things T's keys open are in it.
- `Sync`: nodes exchange per sync ID and log to a store per sync ID. A node syncs each independent thing it holds a ticket or keys for, and every independent thing those sync units hold. It holds only what some sync ID it syncs carries by its own view and drops the rest. A delete-key holder deletes store entries its view does not carry; any node logs what its view carries. Under a sync ID go the commits on its sync unit's things and, as certificates, the role commits on things among its keys.
  - `certify_revokes` also carries a role commit naming a thing among its keys (itself included). That is the fix for the hole below, which the spec states (spec/permissions.md §4 Role changes travel); "by the plan's words" below is the mode without it.
- `closure` walks the node closure sync unit by sync unit. The node's keys and sync secrets are the least sets the independent things it reads yield (a fixpoint over the walk): an open ticket gives its keys only where the walk enters its thing (spec/sync-set.md §4 Declining is doing nothing), and an independent thing reached that the node's keys hold sync on (no read) is kept unread as by a sync-only ticket. Kept unread, the walk stops at it: the node holds it alone (spec/sync-set.md §2). `Walk::Literal` follows every strong the node can open: a mutation kept for contrast.
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
