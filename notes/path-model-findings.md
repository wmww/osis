# Path model findings
> Summary: What the roles-model `paths` module (stated paths, signers as members: notes/write-path-design.md, notes/account-membership-design.md) found in that design: each hole with its scenario, the rule allowing it and a fix or question; what held; what the model does not cover.

The model: core/test/roles-model/README.md (Paths). Each finding has a hand world in `src/paths/tests.rs`: a `repro_*` test, ignored, asserting the wanted behaviour and failing; where a fix is modelled, the test after it passes with the fix. X is the stolen node, H its remover, R the removal, B another node of account A, K a node of the collaborator account A2, T1 a thing A administers.

## Findings
Most serious first.

1. **Removing a node undoes its role writes where the remover did not hold them, removals included** (`repro_a_grant_the_remover_did_not_hold_stands`, `repro_a_removal_the_removed_node_made_stays`).
   - X shared T1 with A2; H does not sync T1; H removes X. R's audit drops the grant, and every write of K falls, with no list made for them. The other direction is a safety matter: X had removed A2 from T1; R drops that removal and A2 writes T1 again.
   - Allowed by: an audit drops every unlisted role write through the lowered edge (write-path §1, Attribution and demotion); addenda vouch for plain content only (spec/permissions.md §5.2).
   - Fix modelled: a vouch (one per thing, naming R and the role writes its writer had received by R's `ts`), counting when its path gives admin on that thing; a counting vouch keeps what it names out of R's audit and R's seeds. Both searches hold with it. The issue names grants only: the fix must cover lowerings alike.
2. **A vouch judged in the walk it changes has no fixpoint** (`repro_a_vouch_judged_in_the_walk_it_changes_settles`).
   - Honest world: X had demoted B to write on A; H never received that; R drops it, so B is an admin again and vouches for its own demotion; the vouch standing, B is no admin at the vouch's key, so it does not count, so the demotion falls, so it counts.
   - Allowed by: the simplest reading of "a remaining holder that could have made the role write itself may vouch", with the voucher's authority read from the same walk.
   - Fix modelled: read the voucher's authority from the walk with no vouch counting (two walks, no iteration). It settles and gives no escalation: a made-up key, or X by a path giving less than admin, vouches for nothing (`a_vouch_gives_nothing_to_whoever_could_not_have_made_the_write`). Its cost is finding 3.
3. **Under that reading a holder kept by a vouch vouches for nothing** (`repro_a_holder_kept_by_a_vouch_vouches_in_turn`).
   - X paired N5 and shared T1; B received the pairing, only N5 the share. B's vouch keeps N5; N5's vouch for the share does not count (N5 is no admin in the walk without vouches), so the share falls.
   - Question: accept (a holder standing only by a vouch saves nothing, as a re-granted writer's addendum saves nothing today, finding 9), or define levels (vouches counting in walk k judge the vouchers of walk k+1, never dropping one already counted). The same-walk reading saves this world and circles on finding 2's.
4. **A removal that does not list its own grant drops what it does not list and then does not apply** (`repro_nothing_falls_by_a_removal_that_does_not_apply`).
   - X (stolen, admin by H's grant) removes H with an empty frontier. The audit drops X's own grant and B's; on the restart X holds nothing, so its removal does not apply, yet both grants stay dropped: B falls with no standing removal, and no dispute is raised (the removal applies under no trust set). A removal of H by a made-up key X granted does the same to X's grant (and so to the made-up key's).
   - Allowed by: write-path §1 removing "R never demotes its own author" on the ground that an honest frontier lists its own chain; a hostile one need not, and D only grows within a walk (spec/permissions.md §5.1 step 5).
   - Fix modelled: keep the rule along paths: a lowering never puts in question the grants its own path rests on (`a_removal_never_puts_its_own_grant_in_question`). The removal then applies and is an ordinary dispute. Alternative: drops made by a write the settled walk does not apply do not count (needs a second fixpoint).
5. **A reader holding only its thing's leaf of a frontier misjudges role writes on A** (`repro_a_reader_with_its_things_leaf_reads_as_a_member`).
   - X paired N5; H received that and lists it, in A's leaf. A reader of T1 holds N5's grant as evidence and R with T1's leaf: it cannot tell the grant was listed, so N5's writes on T1 are invalid at it and valid at A's members. The other way too: a demotion X made, listed in A's leaf, is dropped at the reader, whose roster then differs.
   - Allowed by: membership §4 and its assumption 3 (a reader of T gets R's header, the edge write and the part of R's list about T).
   - Fix modelled: an evidence copy of R carries, beside the unit's own leaf, the leaf entries (with their proofs) for each role commit in that unit's evidence. A leaf per thing then shows such a reader how many role commits X made on A; an entry per commit shows only those it holds.
6. **Both sides of a standing dispute rotate A at every pass, without end** (`repro_a_standing_dispute_stops_rotating`).
   - B sides with X's removal of H. H's epoch is, at B, by a node it holds removed: B withdraws it by rotating, boxing X. B's epoch is valid at H and does not cover X's departure: H re-keys. Two rotations a pass for as long as both are online.
   - Allowed by: spec/crypto.md §4, the knowing re-key (any current epoch not covering a known departure) with the withdraw rule (an epoch not current whose maker may not rotate), as membership §1 `takes` suspected.
   - Fix modelled: an epoch covering a departure the node's walk does not apply is the other side's: read, never current, superseding nothing, neither answered nor withdrawn. One rotation a side; after B's user switches one more (B withdraws its own), then none, and both encrypt under H's epoch, which boxed B all along.
7. **A frontier listing everything received blesses the thief's removal of the remover** (`repro_a_removal_listing_all_it_received_applies`).
   - The thief removes H, honestly stamped, before H acts; H receives it and removes X, listing what it received of X as the rule says. The listed removal stands, H holds nothing at R's key, and R is void under every trust set.
   - Allowed by: spec/permissions.md §5.1 Listed (X's commits as received), with nothing saying what a remover leaves out.
   - Fix (policy, to state): a remover leaves out of its frontier the removed party's lowerings it contests, at the least those of the grants its own path rests on. The same choice decides whether X's removal of another honest node inside the window stands (it does when listed): the user should be asked.
8. **The last-admin rule reads every admin edge of the thing, which a reader's evidence does not hold** (`repro_a_reader_judges_the_last_admin_rule_as_a_member`).
   - H paired B and leaves A (lowers its own edge). A reader of T1 where B never wrote holds H's leaving as evidence and not B's grant: at it the leaving would leave A no admin, is invalid, and H's later writes on T1 show; at A's members they do not.
   - Allowed by: evidence being the edge writes on the edges of held paths (write-path §2); the rule as decided (issue, Removing a thing's last admin) counts edges no path names.
   - Fix to choose: a lowering of an admin edge names an admin edge that remains, which rides in its evidence (modelled as the reader holding that grant); or the rule stays a local refusal.
   - Otherwise the rule is a function of the held writes (`the_last_admin_rule_is_a_function_of_the_held_writes`) and only a lowering through the lowered edge itself can meet it: a removal of another holder always leaves its author's path's last edge.
9. **The collateral grantee** (`repro_a_collateral_grantees_writes_count_after_its_re_grant`): reproduced; counting from the first chained grant fixes it. Two things the fix leaves:
   - a re-granted writer's addendum is valid and vouches for nothing, since its writer held no write at its key in the walk (`repro_a_re_granted_writers_addendum_vouches`): X's writes only N5 received stay lost. Fix: an addendum vouches when it is valid, with no second test of its writer's role.
   - a grant the thief backdates is chained, so a holder granted later may stamp content back to it (`a_backdated_grant_moves_a_current_holders_first_point_back`): no new right, an earlier `ts`. N5's own role writes from the gap stay dropped (finding 1 again, one step on).
10. **A removed node holding write on T by another path vouches for its own backdated writes through the cut path** (`repro_a_write_made_after_the_removal_does_not_show_by_its_signers_addendum`).
    - X, removed from A, still writes T1 through A2: it stamps a write before R stating path [A] and names it in its own addendum by path [A2]. The write shows as A's. It breaks the design's own safety statement (shown only where a remaining writer had received it).
    - Allowed by: spec/permissions.md §5.2 Addenda asking only that the writer hold write on the thing. Fix modelled: an addendum vouches for no commit of its own signer. A colluding writer still can (nothing checks receipt, as today).
11. **Pairing after a fight** (`repro_a_node_paired_after_a_fight_is_a_member_at_itself`): reproduced; with its pairer's trust entries the new node reads as its pairer (`a_node_paired_with_its_pairers_trust_entries_is_a_member_at_itself`). Nothing further found.

## What held
- Safety under the notes' rules as they stand (40,000 random worlds, the thief's moves at any `ts` on any path, a made-up key, removals of honest nodes): no write the thief made after R shows at a node trusting R, but content on a path it still holds (and finding 10); a write on a cut or made-up path never shows by another path; Z and X end with no role.
- With the fixes of findings 1, 2, 4, 5, 9 and 10 (`Rules::fixed`): safety, liveness, alike (readers holding a unit's evidence against members) in 400,000 random worlds and the whole small family (175,104 worlds), no failing check.
- A switch takes: a node on X's side reads as the honest side once its trust set changes, and X's writes from before R that only it received show by the addendum it writes then (`a_switch_takes`); in the keys layer it needs no epoch it was not already boxed.
- Two nodes removing each other never leave A without an admin, in any held subset under any trust set; the walk alone takes the lower key.
- A removal logged only where the node wrote leaves the window Tess's answer closes (`a_removal_logged_only_where_the_node_wrote_leaves_a_window`).

## Not covered
Dependent things and descent; `until`, invites, finalizes and self-removal by path end; snapshots, forgetting and own covers; demotion to write; accomplices granted inside the theft window; sessions and overlapping dots; hidden mode; purge authors; the thief's own rotations of A and secrecy (the keys layer is only the rotation loop under a standing dispute); a user keeping what nobody received; re-keys of things above A and re-seals; bodies a node on the wrong side dropped as invalid (whether a switch fetches them again); how a node picks its side (sides are given); the differential against osis-perm (nothing is built).

## Against the second-round design
Read, not modelled: each finding against notes/account-membership-design.md and notes/write-path-design.md as revised (issues/actors-one-mechanism.md, Answers).
1. Answered as modelled: a vouch by a holder of every right the named write needed, read in the first walk, added to R's list for the second; it covers any role write, lowerings included.
2. Answered as modelled: the first walk reads no vouch; two walks, no fixpoint.
3. Answered: accepted (a holder whose authority only a vouch restores cannot itself vouch; one stage only).
4. Open: write-path §1 still removes "R never demotes its own author" on the ground that R's list names its own chain, and nothing undoes drops made by a write the settled walk does not apply.
5. Open: membership's assumption 3 and its locality property still give a reader of T only T's leaf; a leaf names X's commits on that thing or made through it, so a listed grant on A stays unseen there.
6. Open: membership §1 (`takes`) and §4 (Other gaps) still list the loop as possible; nothing in the revised text ends it.
7. Open: R's list still names every commit through the lowered edge its author received (write-path §1, List scope); nothing says to leave out the lowerings the remover contests.
8. Open: the last-admin rule still reads every standing admin edge as the walk stands (adding only "no `until`"), and evidence still holds only edge writes on held paths' edges.
9. Answered differently: no first-chained re-grant; the collateral grantee stands by a vouch where a remaining admin received its grant, else is discarded, shown to the user and kept only on the user's say-so; re-granted, its earlier content counts from the re-grant and its role writes stay dropped. The backdated-grant cost does not arise; a re-granted writer's addendum still vouches for nothing (left to the user's keep).
10. Open: an addendum is still kept by any writer that could have written the write itself; nothing excludes the removed signer writing by another path.
11. Answered as modelled: the pairer hands over its trust entries (membership §2, Pairing).
