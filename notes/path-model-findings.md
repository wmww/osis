# Path model findings
> Summary: What the roles-model `paths` module (stated paths, signers as members: notes/write-path-design.md, notes/account-membership-design.md) found in that design: each hole with its scenario, the rule allowing it and a fix or question; what held; what the model does not cover.

The model: core/test/roles-model/README.md (Paths). Each finding has a hand world in `src/paths/tests.rs`: a `repro_*` test, ignored, asserting the wanted behaviour under the first round's reading (`Rules::design`) and failing, or a test asserting the hole and its fix side by side. X is the stolen node, H its remover, R the removal, B another node of account A, K a node of the collaborator account A2, T1 a thing A administers, M a mint admin of A who paired H.

## Findings
Most serious first.

1. **Removing a node undoes its role writes where the remover did not hold them, removals included** (`repro_a_grant_the_remover_did_not_hold_stands`, `repro_a_removal_the_removed_node_made_stays`).
   - X shared T1 with A2; H does not sync T1; H removes X. R's audit drops the grant, and every write of K falls, with no list made for them. The other direction is a safety matter: X had removed A2 from T1; R drops that removal and A2 writes T1 again.
   - Allowed by: an audit drops every unlisted role write through the lowered edge (write-path §1, Attribution and demotion); addenda vouch for plain content only (spec/permissions.md §5.2).
   - Fix modelled: a vouch (one per thing, naming R and the role writes its writer had received by R's `ts`), counting when its path gives admin on that thing at its key in the walk with no vouch counting; a counting vouch keeps what it names out of R's audit and R's seeds. Grants and lowerings alike.
2. **A vouch judged in the walk it changes has no fixpoint** (`repro_a_vouch_judged_in_the_walk_it_changes_settles`).
   - Honest world: X had demoted B to write on A; H never received that; R drops it, so B is an admin again and vouches for its own demotion; the vouch standing, B is no admin at the vouch's key, so it does not count, so the demotion falls, so it counts.
   - Fix modelled: read the voucher's authority from the walk with no vouch counting (two walks, no iteration). It settles and gives no escalation (`a_vouch_gives_nothing_to_whoever_could_not_have_made_the_write`). Its cost is finding 3.
3. **A holder kept by a vouch vouches for nothing** (`repro_a_holder_kept_by_a_vouch_vouches_in_turn`).
   - X paired N5 and shared T1; B received the pairing, only N5 the share. B's vouch keeps N5; N5's vouch for the share does not count (N5 is no admin in the walk without vouches), so the share falls. Accepted (membership §4, No circle). Addenda are not limited so: they are judged in the settled walk, so a writer kept by a vouch vouches for content.
4. **A removal that does not list its own grant drops what it does not list and then does not apply** (`repro_nothing_falls_by_a_removal_that_does_not_apply`).
   - X (stolen, admin by H's grant) removes H with an empty frontier. The audit drops X's own grant and B's; on the restart X holds nothing, so its removal does not apply, yet both grants stay dropped and no dispute is raised.
   - Fix modelled: a lowering never puts in question the grants its own path rests on (`own_chain_exempt`, `a_removal_never_puts_its_own_grant_in_question`). The removal then applies and is an ordinary dispute.
5. **A reader holding only its thing's leaf of a frontier misjudges role writes on A** (`repro_a_reader_with_its_things_leaf_reads_as_a_member`).
   - Fix modelled: a reader holding R sees the entry, present or absent, of each role commit in the evidence it holds (`Rules::evidence_leaves`).
6. **Both sides of a standing dispute rotate A at every pass, without end** (`repro_a_standing_dispute_stops_rotating`).
   - Fix modelled: an epoch covering a departure the node's walk does not apply is the other side's: read, never current, superseding nothing, neither answered nor withdrawn (`Withdraw::SideOnly`).
7. **A frontier listing everything received blesses the thief's removal of the remover** (`repro_a_removal_listing_all_it_received_applies`).
   - The thief removes H, honestly stamped, before H acts; H receives it and removes X, listing it. The listed removal stands, H holds nothing at R's key, and R is void under every trust set.
   - Fix modelled: an entry of R's list (frontier or counting vouch) naming a write that lowers an edge of R's own stated path below admin is read as absent (`ListOwn::Hops`; `a_removal_listing_the_thiefs_removal_of_its_author_applies`; story: `Setup::x_first`, property `own path`). Every other lowering X made stays made (`a_lowering_the_removed_node_made_before_stays_made`), and a node X removed earlier that writes a junk grant to H stays removed (`a_removed_node_writing_a_grant_to_the_remover_stays_removed`). Its reach beyond the path's own edges: finding 12.
8. **The last-admin rule reading every admin edge of a thing splits readers from members** (`repro_a_reader_judges_the_last_admin_rule_as_a_member`).
   - H pairs B and leaves A. A reader of T1 where B never wrote holds H's leaving and not B's grant: it refuses the leave and shows H's later writes; A's members do not.
   - Fix modelled: an unmarked write taking a standing admin edge (admin, no `until`) to anything else applies only where the remaining admin it relies on is a standing admin edge other than the lowered one: its path's last edge, else the holder it names, whose edge writes are its evidence (`LastAdmin::Named`; `a_reader_judges_the_named_last_admin_rule_as_a_member`). A timed admin is no remaining admin (`a_timed_admin_is_no_remaining_admin`: counted as one, a thing goes adminless on a date with no marked write).
9. **The collateral grantee** (`repro_a_collateral_grantees_writes_count_after_its_re_grant`): fixed by counting a re-granted path from each edge's first chained grant (`Regrant::FirstChained`). A grant the thief backdates is chained, so a holder granted later may stamp content back to it (`a_backdated_grant_moves_a_current_holders_first_point_back`): no new right, an earlier `ts`. A re-granted writer's addendum written before its new grant vouches for nothing; the one it writes after does (`a_re_granted_writers_later_addendum_vouches`; the state-based writing writes it).
10. **A removed node vouches for its own backdated writes through the cut path** (`repro_a_write_made_after_the_removal_does_not_show_by_its_signers_addendum`).
    - X, removed from A, still writes T1 through A2: it stamps a write before R stating path [A] and names it in its own addendum by path [A2]; the same with a grant and its own vouch where X administers T1 through A2.
    - Fix modelled: no addendum or vouch counts for a commit of its own signer (`no_own_addendum`, `no_own_vouch`; `a_removed_signer_vouches_for_nothing_of_its_own`; story: thief move 19). A colluding writer still can (nothing checks receipt, as today).
11. **Pairing after a fight** (`repro_a_node_paired_after_a_fight_is_a_member_at_itself`): with its pairer's trust entries the new node reads as its pairer (`a_node_paired_with_its_pairers_trust_entries_is_a_member_at_itself`).
12. **What no list keeps, read from the stated path alone, does not reach the grants that path rests on** (`a_removal_listing_the_thiefs_removal_of_its_granter_is_void`).
    - M (mint) paired H and X. X, stolen, removes M listing nothing, which drops M's grant of H; H receives it and removes X, listing it. R's path is [H on A]: the entry lowers (M, A), not an edge of R's path, so it is kept, and R is void under every trust set. Every account whose remover is not its mint admin is exposed: the thief removes the remover's pairer first.
    - The notes state the rule for "an edge a grant on that path itself rests on" too, read as absent by every node (membership §4 What no list keeps; write-path §1). No reading of it found is both checkable by every node and safe:
      - read from the held grants on the path's edges, closed (`ListOwn::Chain`): a removed node writes a junk grant to the remover and strikes the remover's listing of its own earlier removal (`a_removed_node_writing_a_grant_to_the_remover_stays_removed` fails under it);
      - read from the walk: the grants R rests on are those standing at R in the walk where R applies, which R's own seeds decide (circular); an auxiliary walk (R's list read as keeping none of X's lowerings) admits a removed node's grant to the remover backdated before its own removal (argued, not modelled).
    - Alternative that holds in the model: the rule over the path's own edges as the reader's check, and a writer policy for the rest: a remover leaves out of its list, and a witness out of its vouch, every lowering of an edge its own walk shows the removal's path resting on. With the entry left out R applies (same test). Readers cannot check that policy; a lying witness's vouch then voids R where an admin accomplice could remove H outright anyway.
13. **A re-granted grantee vouches for its own fallen grant** (`a_re_granted_grantee_vouches_for_its_own_fallen_grant`).
    - X paired N5 (H never received it); N5 wrote content and a grant; R drops N5's grant and all of it. H pairs N5 again. N5, admin again in the first walk and holding X's grant of it from before R, vouches for it by the writing rule (it is X's commit, not N5's): the grant applies at its own key and N5's gap writes stand, role writes included.
    - Contradicts membership §4 (What follows, "re-granted without a vouch ... its earlier role writes stay dropped"; No circle, "the beneficiary of a fallen grant has no authority in the first walk, so cannot vouch for its own grant": true only until re-granted). With the state-based writing it happens wherever the grantee is re-granted, so `Regrant::FirstChained` is not reached by the story.
    - It follows from the rule's principle (a remaining party that could write it had received it); a re-grant is an admin's act. Question: accept, or extend "nobody vouches for its own signer's commit" to a commit setting the voucher's own edge.
14. **A removed node's backdated self-removal undoes its own earlier role writes** (`a_backdated_leave_undoes_nothing_the_removed_node_made`).
    - X, stolen, leaves A by a self-removal stamped before role writes it made honestly (a demotion of B, a pairing of N5), which H received and lists. A self-removal audits nothing and states no hop through (X, A), so no audit reaches it; X held no admin at its later writes, so they fall: X's demotion of B is undone, N5 is no member.
    - Allowed by spec/permissions.md §5.1 Seeds ("except a write lowering its author's own edge") and the self-removal's path ending at its holder (write-path §1, The end): no lowering puts it in question.
    - Fix modelled (`Rules::leave_in_question`): a lowering of edge h puts a self-removal of h in question like a write through h; unlisted, the backdated leave is dropped. Honest leaves before R are received and listed. Alternative: R's audit judges the victim's later writes against the edge as restored (which already counts what a self-removal took), never against the current value.

## What held
- Under `Rules::fixed` (every fix above): safety, liveness, alike (readers holding only the commits on the things they read and those commits' evidence, against members), the remover's path kept, the last admin standing, no stray drop or void trusted removal: 400,000 random worlds and the whole small family (README.md, Paths, for counts). Each rule's negative control fails the search.
- Descent: a write to a dependent is judged along the record edges down its mint chain; lowering a descent edge audits every path through it (`a_write_by_descent_is_judged_along_the_record_edges`). Validity reads record edges only, so a thing on a path becoming independent changes no verdict (nothing in the model reads independence).
- Self-removal by path end audits nothing and raises nothing (`a_self_removal_by_path_end_audits_nothing`, `a_self_removal_raises_nothing`); a removal after it audits against the edge as restored (`a_backdated_leave_shields_nothing_from_the_removal`). An `until` passing audits nothing; the next explicit write on that edge does (`an_until_passing_audits_nothing_the_next_explicit_write_does`).
- The state-based writing (a node writes whenever its own walk shows an owed commit it could write that nothing of its own covers) holds liveness under stated paths; answering only the first time a node's walk applies R fails it (a witness standing by a vouch, a re-granted writer).
- A switch takes (`a_switch_takes`); two nodes removing each other never leave A without an admin; a removal logged only where the node wrote leaves the window Tess's answer closes (`a_removal_logged_only_where_the_node_wrote_leaves_a_window`).

## Not covered
Invites and finalizes; purge authors; own covers and forgetting (so "a writer that compacts before holding the removal carries the thief's write" is not reached); demotion to write (a kiosk); accomplices granted inside the theft window; sessions and overlapping dots; hidden mode; the thief's own rotations of A and secrecy (the keys layer is only the rotation loop under a standing dispute); re-keys of things above A and re-seals; bodies a node on the wrong side dropped as invalid; how a node picks its side (sides are given); finding 8's reader shape in the story (the reader of T1 always holds R and so the remover's chain, so the any-edge control fails only by hand); the differential against osis-perm (nothing is built).

## Where the design answers each
Against notes/account-membership-design.md (membership) and notes/write-path-design.md (write-path). "Modelled" means the rule is the one `Rules::fixed` checks; "argued" means the note states a rule the model does not hold.
1. Membership §4, Role writes: modelled.
2. Membership §4, No circle: modelled.
3. Membership §4, No circle: accepted, modelled.
4. Write-path §1, A lowering stands on its own path, first half: modelled.
5. Membership §4, The list: the reader seeing those entries modelled; the position per commit argued.
6. Membership §1, `takes`: modelled.
7. Membership §4, What no list keeps; write-path §1: modelled over the stated path's own edges. The clause "or an edge a grant on that path itself rests on" contradicts the model (12).
8. Write-path §5, The last admin: modelled, timed admins and the mark included.
9. Membership §4, What follows and Writing: modelled; but see 13.
10. Membership §4: modelled for addenda and vouches.
11. Membership §2, Pairing: modelled.
12. Open: the notes' statement fails (above); the writer-policy alternative is not in the notes.
13. Open: contradicts membership §4 as written; the principle allows it.
14. Not in the notes: spec/permissions.md §5.1 Seeds' exception and write-path §1 (self-removal audits nothing) allow it; the modelled fix is new.
