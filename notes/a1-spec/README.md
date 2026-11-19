# A1 spec draft: the map
> Summary: Stage A1's spec text drafted before any code brief (notes/redesign-plan.md, A1): per draft section the spec section it replaces, the roles-model `paths` check that is its oracle, and its status (SETTLED, PENDING MODEL, OPEN); the open questions with options and costs; where the model overrode the design notes; what A1 removes from spec and every heading or anchor that breaks; the order in which code briefs move the text into spec/; the walk checked clause by clause against core/test/roles-model/src/paths.rs; why MAX_PATH_THINGS is 64.

Draft files: notes/a1-spec/wire.md, notes/a1-spec/commits.md, notes/a1-spec/permissions.md, notes/a1-spec/crypto.md. Each holds the words that will stand in spec/ for every section A1 changes; a bullet marked *Stands* keeps today's words. Sources: notes/write-path-design.md §1-§6, notes/account-membership-design.md §1-§4 and §8, notes/path-model-findings.md, core/test/roles-model/README.md (Paths). Accounts are unchanged at A1: today's account key is the signer of a path that starts above it, so a node writing as its account states the empty path.

**Statuses.** SETTLED: the rule is held by roles-model `paths` under `Rules::fixed` (reviewed, on main). PENDING MODEL: invites, finalizes, purge authors, own covers and forgetting are being modelled on another branch; those sections are written from the design notes, marked at their top, for the modeller's result to be dropped in. OPEN: a decision the design has not made (below); where the draft needed one, it takes the option marked *taken*.

## The map
| draft section | replaces | oracle (roles-model `paths`) | status |
|---|---|---|---|
| wire §4 fields 1, 2: `signer`, `path` (one for all, one per thing hashed), `Salted` in sections | spec/wire.md §4 fields 1, 2, Commit blob | `World::push` (members, `well`), `World::joins` (descent); bytes per notes/write-path-design.md §1 (Where the path sits) | SETTLED (rule); bytes OPEN 6 |
| wire §4 field 8 (`[tid, ak, author]`), field 11 (level-2 keys), the purge-author index | spec/wire.md §4 fields 8, 11 | none yet | PENDING MODEL |
| wire §4 fields 14 to 16 (`epoch`, `rotation`, `reseal` keyed to the signer) | spec/wire.md §4 fields 14 to 16, Inner signature | none (a rename; accounts unchanged) | SETTLED |
| wire §4 field 17 `remains`, field 18 `flags` | spec/wire.md §4 field 17 | `LastAdmin::Named`, `refused` (`relies`), `evidence_edges` | SETTLED (rule); position OPEN 7 |
| wire §4 Inline or link, §5 header-list commitment, crypto §7 thing blind | spec/wire.md §4, §5; spec/crypto.md §7 | none | OPEN 8 |
| wire §2 MAX_PATH_THINGS, §12 | spec/wire.md §2, §12 | none (a decode bound) | SETTLED (Why 64, below) |
| commits §1, §3 | spec/commits.md §1, §3 | none (who a commit is by: `Commit::signer`) | SETTLED |
| commits §4 Each delta, Unjudgeable, Examined again | spec/commits.md §4 | `judge` along `World::hops`; `evidence` (edges of held paths) | SETTLED |
| commits §4 Received | spec/permissions.md §5.1 Received (moved) | the story's receipt times (`Sim::received`) | SETTLED (today's words) |
| commits §4 Could hold the right; §5 sentences | spec/commits.md §4 (possible admins, possible writers, could hold the right), §5 | none yet | PENDING MODEL |
| crypto §7 | spec/crypto.md §7 | none yet | PENDING MODEL |
| permissions §1 Signer, Path | spec/permissions.md §1 Actor | `World::push`, `World::joins`, `a_write_by_descent_is_judged_along_the_record_edges` | SETTLED |
| permissions §1 The last admin | spec/permissions.md §1 The last admin | `refused` under `LastAdmin::Named`; `a_reader_judges_the_named_last_admin_rule_as_a_member`, `a_timed_admin_is_no_remaining_admin`, `the_last_admin_rule_is_a_function_of_the_held_writes`; controls `-any-edge`, `-timed` | SETTLED (OPEN 5, 9) |
| permissions §2 Edge writes, Self-removal, Adminless mark, Logging a lowered grant | spec/permissions.md §2 | `walk` (a self-removal only lowers), `rests_on` with `leave_in_question`, `a_self_removal_by_path_end_audits_nothing`, `a_backdated_leave_undoes_nothing_the_removed_node_made`; control `-leave` | SETTLED |
| permissions §2 Finalize, Path's invite, Invite grant | spec/permissions.md §2 | none yet | PENDING MODEL |
| permissions §4 lead, Chained writes, Chain certificates, path chain | spec/permissions.md §4 | `first_chained`; `evidence` with the alike property (readers holding a unit's evidence read as members) | SETTLED (transitional: A2 deletes it); invites and finalizes PENDING MODEL |
| permissions §5.1 steps 1-5, terms, Nothing is exempt | spec/permissions.md §5.1 steps 1-5 | `walk`, `keeps`, `settle`, `judge`; every property of the Paths table; controls `-no-void`, `-exempt`, `-audit-applied`, `-once` | SETTLED (OPEN 1-4, 10) |
| permissions §5.1 Frontier | spec/permissions.md §5.1 Frontier | `World::through` (what an honest frontier names), `listed` | SETTLED; its Own cover PENDING MODEL |
| permissions §5.1 The list | spec/permissions.md §5.1 Vouches (its last bullet) | `Sim::stand`, `Sim::vouchable`, `Sim::applies`; controls `-listed`, `-key-order`; `a_list_keeping_what_unmakes_its_removal_voids_it`, `a_remover_keeps_what_it_received_first` | SETTLED |
| permissions §5.1 Trust set, Seeds, void, dispute | spec/permissions.md §5.1 Trust set | `seeds`, the redo loop of `judge`, `disputes`; properties `quiet`, `dispute`, `untrusted`; `a_dispute_whose_write_is_a_no_op_where_trusted_is_shown` | SETTLED (OPEN 3) |
| permissions §5.1 Vouches | spec/permissions.md §5.1 Vouches | `settle` under `Vouch::BaseWalk`, `counting` with `no_own_vouch`; `a_vouch_counts_only_where_its_removal_applies_in_the_first_walk`, `a_removed_signer_vouches_for_nothing_of_its_own`; control `-own-vouch` | SETTLED |
| permissions §5.2 Content, cut, Addenda, Re-grant | spec/permissions.md §5.2 | `content` (`cuts`, `no_own_addendum`, `Regrant::FirstChained`); `a_re_granted_writers_later_addendum_vouches`, `a_backdated_grant_moves_a_current_holders_first_point_back` | SETTLED |
| permissions §5.2 External fires, admin-only, Copies, Ephemeral parts | spec/permissions.md §5.2 | none (wording: signer, path) | SETTLED |
| permissions §5.2 Compaction snapshot, its Own cover, A cover is its signer's edit | spec/permissions.md §5.2 | none yet | PENDING MODEL |
| permissions §6 | spec/permissions.md §6 | none yet | PENDING MODEL |

## Where the model overrode the design notes
Each is written as the model has it.
1. **Dispute candidates** (`disputes`): every held edge write giving below admin at its `ts` on a grant whose holder is not its signer (self-removals through a holder thing included), not trusted and not dropped by a trusted write, by its seeds or by its drops. notes/write-path-design.md §1 says "a held lowering of another holder's edge ... not dropped by a trusted write's seeds".
2. **The remaining admin's own edge** (`refused`): the edge from the path's last listed thing (the signer for an empty path) to T. A path reaching T by a descent of two steps or more has no such edge and names one. The design says "the last edge of the write's own path" (OPEN 9).
3. **The last-admin rule is read only by a part without a verdict**, before its drops (`refused` is skipped for `Verdict::Applied`; it reads the pass's state at the write). The design leaves both unsaid (OPEN 5).
4. **A vouch is an edge-class part of the walk** (`edge_class`, `order`): it applies iff its path gives admin on its thing at its key, is ordered by key, and is put in question and dropped by lowerings of its path's edges like any part. Today's spec/permissions.md §5.1 Vouches orders a vouch by its position and asks "W could write c" at each later lowering of W; the walk gives both.
5. **Re-grant from each edge's first chained write** (`Regrant::FirstChained`, `first_chained` along stated paths, strictly after its key). notes/account-membership-design.md §4 says so; today's spec/permissions.md §5.2 reads the first point the walk gave the role.
6. **Edge as restored is a role** (`Pass::restored`): the highest role since the last explicit write, the record edge admin from the start. Today's spec joins role, invite and `until`; invites are PENDING MODEL.
7. **Seeds and drops reach a self-removal of the lowered edge** (`leave_in_question`): today's spec/permissions.md §5.1 Seeds exception ("except a write lowering its author's own edge") goes.
8. **Only a lowering taking its edge from admin drops edge-class parts**; a cut from write drops nothing in the walk and cuts content only (`walk`: `before == Role::Admin`; `content`: `cuts`).
9. **The writers' list** (`Sim::stand`): where R, trusted, applies with everything received it lists everything; else the content, then the role writes one at a time in receipt order (ties by commit ID), each kept iff R still applies. The design says "leaving out a role write with which R ... would be void".
10. **Self-removal by path end**: a signer leaving by itself states the empty path and no edge (`World::push`: `leave`).

## Open
Each is a question with its options; *taken* marks what the draft writes meanwhile.
1. **What a removal's result names** (notes/path-model-findings.md 19): the members a kept lowering of the remover by X dropped, beside those X lowered. (a) Only X's own lowerings (*taken*: no spec text; it is the `osis` result): a co-admin's loss is not shown. (b) Also every part a lowering the list keeps dropped: the remover's walk computes it, one diff of two readings. (c) The writers' rule leaves out a lowering of the remover even where R applies with it: reopens the key-order class (control `-key-order`). The spec is unaffected in (a) and (b).
2. **The void check's cost** (notes/path-model-findings.md 17): k void lowerings at the end of a chain of k grants cost k² setters read, all forced by one party's own 2k role writes. (a) Cap nothing and state the cost (*taken*: the spec caps nothing; A1 brief 7 counts it). (b) Memoize chain reads across checks with the same drops on the chain: linear for this attack, not in general. (c) A cap on the depth `keeps` reads: the verdict would depend on the cap, which notes/arbitrary-values.md rejects (a correctness value). MAX_PATH_THINGS bounds one path, not a chain of grants.
3. **Detecting disputes at a node that trusts nothing** (notes/path-model-findings.md Open 0): the rule is a walk with each candidate trusted, so k held candidates cost k walks of their component per change. (a) The spec defines the dispute and leaves when it is computed to the node (*taken*). (b) Narrow the candidates to lowerings the walk leaves without a verdict or applies with drops that dropped a lowering or a grant a lowering applied under (the classes of findings 16 and 21): needs a model run showing nothing is missed. (c) Compute on demand (a view of a thing's roles): a dispute is then shown late.
4. **The adminless reading at untrusting nodes** (`a_lowerings_check_does_not_read_what_its_drops_free`, one `tiny` world in 1,000,000): a lowering's check does not see what its drops free, so A can be left with no admin where nothing is trusted, shown as a dispute whose trust restores an admin. (a) Accept, stated (*taken*: nothing in the draft). (b) Replay from the earliest drop before giving the verdict: a walk per check. (c) Read the last-admin rule again after the drops: circular with the verdict.
5. **A remaining admin taken by the lowering's own drops**: the rule reads the walk before the drops, so a lowering naming B, whose grant it drops, applies and may leave no standing admin; only the writer's MUST covers it. (a) As modelled (*taken*). (b) Add the remaining-admin edge to `keeps(L)`: L void where its drops take the admin it names: one more edge per check; needs a model run.
6. **Path bytes**: the one-for-all form told from the per-thing form by its first item (a uint against byte strings); the hash `kdf("path", salt, Path)` with 16-byte salts; `Salted` inside each section's `Contents` (so in both of a thing's sections and in copies). *Taken* as written; the design names only `BLAKE3(salt ‖ path)` and "the thing's section carries the salt and the path".
7. **Where the remaining admin goes**: (a) a header field `remains` at position 17, `flags` moving to 18 (*taken*: one byte on every commit, every "field 17" citation swept); (b) after `flags`, which then cannot stay optional; (c) in the `roles.0` value (a removal has none); (d) in `Path` (it is per edge write, not per thing written).
8. **Header-list chunks' delete key** (they committed to the actor's level-2 key): (a) the signer's delete key (*taken*: the party that could delete them today still can); (b) an empty group: deleted only by the sync ID's delete key or at expiry, one mechanism less.
9. **The remaining admin by descent** (override 2): (a) as modelled (*taken*): a write reaching T by a descent of two steps names its remaining admin; (b) read the last hop (T's record edge): needs a model run.
10. **A commit with several lowerings** (a removal of several holders on one target, spec/commits.md §2): not modelled. *Taken*: each is judged on its own against the state before the commit (step 2), and a pass ending at one ends once the whole commit has taken effect. Whether the second's `keeps` reads the first's drops is unanswered.
11. **"Its actor's secrets"** in spec/commits.md §4 Examined again and Hostile input: read as the signer's secrets in the draft; the brief moving §4 checks what the engine awaits there.

## What A1 removes from spec
- The header's `author` and `actor` (spec/wire.md §4 fields 1, 2), "in a role commit equal to `author`", and "actor equal to author" in `rotation` and `reseal`.
- The Acting check and "Role commits act for their author" (spec/permissions.md §5.2 Acting), "A delta is judged by its author's authority, whatever its header actor" (§5.2), the addenda's "or the Acting check" and "acting for a thing other than its author" (§5.2 Addenda), and "acting for one of those things" (§5.1 Frontier, Listed).
- "Losing a path while another keeps the class is no fall" (§5.1 step 4), with steps 3 and 4 whole (authority classes, "demotes", "R never demotes its own author") and step 2's attribution bullets.
- The audit's reachability search: "on every thing N reaches by edges standing at that point" (§5.1 step 4) and the seeds' "by any author that reaches M over record edges and admin edges chained writes set" (§5.1 Seeds).
- The certificate search over any path: "the things on any path from X to the thing over record edges and the edges chained writes set" (§4 Chain certificates).
- The writer-only last admin: "It is the writer's check, not a validity rule" (§1 The last admin) and "only that check reads it" (§2 Adminless mark).
- Self-removal's "admin on X is the author's only authority for it" (§2) and effective invite in validity (§2).
- Possible admins and possible writers (spec/commits.md §4); "Purge requests" in the frontier (§5.1, as its own clause: a request resting on the edge is listed as any commit).
- "A header actor that lost write on the thing gives no author's right" (§6).
- Today's dispute clause ("which the settled walk does not apply ... with a value below the edge's value", §5.1 Trust set).

## Headings and anchors that break
Each breaks citations; the code brief that moves the section sweeps them (`spec/... §N (anchor)` in test comments: tools/spec_map.py).
- spec/permissions.md §1: bold **Actor** becomes **Signer**; **Path** is new.
- spec/permissions.md §2: **Effective invite** sentence becomes **Path's invite**.
- spec/permissions.md §4: heading "Verifying authors: certificates" becomes "Verifying signers: certificates"; "author's chain" becomes **path chain** (cited in spec/sync-judgement.md, spec/commits.md, spec/sync-inbox.md, spec/crypto.md, spec/wire.md and 9 notes).
- spec/permissions.md §5.1: steps 3 and 4 change meaning (Judging a lowering, Keeps); citations of "§5.1 step 4" (spec/wire.md field 12, spec/commits.md §1, spec/crypto.md and 25 code files) and "§5.1 step 2" now point at the new steps; **Received** moves to spec/commits.md §4; the frontier's **Aspects in question**, **Listed** and **Purge requests** go; **W could write c at a point** goes; **The list** and **Nothing is exempt** are new.
- spec/permissions.md §5.2: **Acting** goes.
- spec/wire.md §4: field 17 becomes `remains` and `flags` moves to 18 ("field 17" in spec/permissions.md §5.1 and §5.2 Own cover, "position 17" in §2, 9 code files).
- spec/commits.md §4: **possible admins**, **possible writers** go; **Received** is new.
- Anchors tests cite whose words go: spec/permissions.md §5.2 (acting), (Acting), (addenda; acting); §5.1 (never demotes its own author), (frontier; aspects in question), (demotes; aspects in question), (audits: falls, security), (frontier received); spec/wire.md §4 (the epoch an account author signs at).

## Also changes, not drafted
Sentences outside the drafted sections that name a commit's author or actor, for the brief that moves the term (notes/principles.md, Complete refactors):
- spec/crdt.md §8 `Facts`: "its header actor where that is not its author" becomes its purge author where that is not its signer; `Absorbed`'s author's tid becomes the signer's (PENDING MODEL with purge authors).
- spec/permissions.md §5.5: "acting for T" in the Epoch rule and Rotation's list, "as for Acting, §5.2", "Demoting an account ... with the account as author"; §7: "the sharer's header actor" (K's mint admin and only admin) becomes the last thing of the sharer's path; §4 Logging certificates, Stranded and the promoter bullet ("author's chain").
- spec/sync-transport.md §6 ("that actor in the header's actor field"), spec/wire.md §11.2 (a client's "header's actor"), spec/sync-judgement.md (Acting).
- "Author" for a commit's signer throughout spec/ (spec/commits.md alone has about 40): the brief moving spec/commits.md §1 sweeps it.
- spec/data-model.md "effective invite"; notes/arbitrary-values-table.md gets the MAX_PATH_THINGS row when it is built.

## Order of the code briefs
Each step lands spec and code together, so every commit on main has them agreeing (plan A1 briefs 2 to 7).
1. **Header and commit crate** (brief 2): spec/wire.md §2, §4 fields 1, 2, 8, 11, 12, 14 to 16, Section, Inline or link, §5, §12; spec/commits.md §1, §3, §4 (Each delta, Received, Unjudgeable, Examined again); spec/crypto.md §7's thing blind. Interim sentence in spec/permissions.md §5.2 in place of Acting, so the old walk still runs: a commit's actor is, on each thing, the last thing its path lists (its signer for the empty path), the same for every thing it writes, else the commit is invalid; its purge author is that actor. The conformance vectors (core/test/vectors) and every fixture are regenerated here.
2. **Engine writing states real paths** (from brief 5): the session's default path (`Write::act_as` states a path), the engine finding the path whose first holder is nearest the signer, CLI; judged still by the old walk, which accepts every real path. No spec change but the Interim's.
3. **osis-perm walk by path** (brief 3), against `paths` as its differential: spec/permissions.md: §1 Signer, Path, Effective role; §2 Edge writes, Self-removal; §4 Chained writes; §5 lead; §5.1 whole but The list; §5.2 whole but the PENDING MODEL bullets; the Interim goes, with Acting. held-model follows.
4. **Purge author and delete keys** (brief 4, once modelled): spec/wire.md field 8, 11; spec/crypto.md §7; spec/commits.md §4 Could hold the right, §5 sentences; spec/crdt.md §8 Facts; spec/permissions.md §6.
5. **Engine: lists and certificates** (rest of brief 5): spec/permissions.md: §5.1 The list (the writers' rule, with vouch writing), §4 Chain certificates and path chain (`sync/certified.rs` narrowed to the stated path), §2 Logging a lowered grant.
6. **The last-admin rule** (brief 6): spec/wire.md field 17 `remains` and `flags` to 18; spec/permissions.md §1 The last admin, §2 Adminless mark; the engine names the remaining admin.
7. **Counting** (brief 7): no spec text.
Invites, finalizes and own covers move into spec/ with step 3 or 5, as their models land.

## The walk, clause by clause
Each sentence of the monotone walk (notes/write-path-design.md §1, Each lowering is judged once) against core/test/roles-model/src/paths.rs; the draft states it in permissions §5.1 steps 1 to 5.
| clause | paths.rs | verdict |
|---|---|---|
| A lowering is an explicit write giving its edge h below admin at its `ts` | `walk`: `w.lowers(i).is_some() && !w.leave(i)` | same (invites, finalizes not modelled) |
| The walk is a run of passes; each starts from the record edges | `walk`: `Pass::default()`, then every `w.records` edge admin | same |
| takes the held edge-class writes in key order (`ts`, signer, commit ID), skipping D | `order` (edge-class: edge writes and vouches, sorted by `World::key`); `dropped.contains(&i)` skipped | same; the model's edge-class includes vouches, as the draft does |
| Two things carry from pass to pass: D and a verdict per lowering | `dropped`, `verdict` live outside the pass loop | same |
| A lowering with a verdict is not checked again: applied, it applies, auditing nothing; void, it is skipped | `match judged`: `Some(Verdict::Applied) => {}`, `Some(Verdict::Void) => continue`; the audit and `refused` run only for `judged.is_none()` | same; the model also skips the last-admin rule for an applied verdict (override 3) |
| Any other write applies iff its path gives what it needs there, and the last-admin rule | `w.well(i)` and every hop `p.at(e, c.ts) == Role::Admin`; `refused`; a self-removal only lowering | same (needs are admin for every modelled kind) |
| A lowering with no verdict that applies and takes h from admin, as restored, to below is judged | `judged.is_none() && !leave && before == Role::Admin && after < Role::Admin`, `before` the restored role (`p.restored` joined with `p.at`) | same |
| Its drops are the held writes ordered before it resting on h, not in D and not void, that its list does not name | `audit_held`: `order[..k]` not in `dropped`, verdict not `Void`; `gone`: `rests_on` and not `listed` | same |
| It is void iff `keeps(L)` fails | `self_void && !keeps(..)` | same |
| `keeps(W)`: every edge of W's path keeps admin, reading the writes this pass applied on it before W's key, latest first | `keeps`: `p.hist[e]` reversed, filtered `x.0 < key` | same |
| pass over each of L's drops | `if gone(j) { continue }` | same in effect: `gone` is "rests on h, not listed", without "before L, not in D, not void"; every write `keeps` reads was applied in this pass before W, so it is all three |
| and each grant (a write giving admin at its `ts`, not a self-removal) for which `keeps` fails | `w.lowers(j).is_some() \|\| w.leave(j) \|\| keeps(..)`: a write that is neither a lowering nor a self-removal is read only if it keeps | same |
| the first one left decides (e keeps admin iff it gives admin at W's `ts`) | `admin = Some(alive(v, ts) == Role::Admin)`, `ts` W's | same |
| with none left e keeps admin iff it is a record edge | `admin.unwrap_or_else(\|\| w.records.contains(&e))` | same |
| Each step reads only writes ordered before the one it checks; it reads the pass's state, walks nothing again | the `x.0 < key` filter on this pass's `hist`; a memo per check | same (the memo is the model's) |
| Void, L does not apply and drops nothing | `verdict.insert(i, Verdict::Void); continue` before the state changes | same |
| Otherwise applied: it applies; its drops join D and the pass ends there | state updated, `dropped.insert`, `break` | same for one edge write per commit; the draft ends the pass once L's commit has taken effect (OPEN 10) |
| The next pass replays the writes before the earliest drop unchanged and walks on from it | `from` = the earliest drop's position; the next pass walks from the records again and counts `walked` from `from` | same reading; the model recomputes rather than resuming |
| A lowering that applies without taking h from admin audits nothing and gets no verdict; one that does not apply gets none; a later pass judges it | no `verdict.insert` on those branches | same |
| A lowering goes at most once from no verdict to one | `verdict.insert` only under `judged.is_none()` | same |
| The walk ends at a pass that adds nothing to D | `if let Some(r) = restart { continue }`, else return | same |
| Nothing is undropped | `dropped` is only inserted into | same |
| The check does not see what L's drops free | `keeps` reads the pass as it stood at L | same |
| Trusted writes: seeds start D | `seeds` (held edge-class before R resting on its edge, not listed) into `walk`'s `d0` | same; no own-edge exception (override 7) |
| A trusted write the settled walk does not apply is void and loses its seeds, all at once, the walk redone from scratch | `judge`: `gone` (trusted, not applied) removed from `active` all at once, `settle` again | same; the redo covers both vouch walks (`settle`), as the draft says |
| (edge as restored) the highest role since the last explicit write, values an `until` or self-removal took included | `p.restored` set by explicit writes only (`if !leave`), joined with `p.at` | same, a role only (override 6) |

## Why MAX_PATH_THINGS is 64
A resource bound against hostile input (notes/arbitrary-values.md). At 0 no write could go through a holder (a node writing its account's things states the account), so the bound is at least the deepest nesting of holders anyone builds. Without a bound one part costs every reader a point query per edge and the edge history of every edge it names as evidence, closed under those writes' own paths, in proportion to nothing the writer pays for. 64 is `MAX_CHAIN_DEPTH`'s value, the depth of a record chain, so a path's edges number at most 64 descents of 64 steps; a writer refuses a longer path, a decoder rejects it.

## Vouches and addenda, sentence by sentence
Against spec/permissions.md §5.1 Vouches and §5.2 Addenda as they stand.
- Vouches: the definition stands but "its delta needs no role on N, each entry counting or not by the rules below" and the position (a vouch is an edge-class part that applies along its path: override 4); "voucher is its commit's author" reads signer; First walk stands ("every vouch's entries unread", the vouch parts still walked); "W could write c at a point" goes; of the counting conditions, the first stands (signer for author), the second becomes "V applies, ordered after R" with "c rests on R's edge" for "in question at R", the third's "W could write c at V's position" goes into the vouch applying, the fourth (each later lowering of W) goes into the walk dropping V, and "not signed by V's signer" is new; Second walk stands ("drops" for "audits"); Writing changes (resting on h, the writers' list, never one's own commit, "applies at the present position" for "could write c"); What vouches keep gains "not signed by its voucher" and "with which R still applies"; Nothing checks stands; the last bullet changes (a kept part taking R's authority voids R).
- Addenda: the definition stands; the first condition becomes a cut of the delta's path; the second reads the addendum's path; "not signed by W" is new; content and A is valid stand ("signer" for "author"); "acting for a thing other than its author" goes; the two "every frontier counts" sentences read cuts; Nothing checks stands; Writing changes (a path with edge h for "of X", "acting for N" gone, never one's own commit).
