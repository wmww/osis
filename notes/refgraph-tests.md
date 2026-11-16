# Reference graph tests
> Summary: The test plan for issues/reference-graph.md (Execution step 6): 38 properties in what users observe, the cheapest test of each with its crate and lane, the new sync differential and sim set against held-model `closure`, the surviving tests the set replaces, the order to write them in, and the count/CPU budget against the 3,493-test, 2,372 CPU-s baseline.

## Budget
Costs per test at baseline (`~/osis-refgraph-baseline/pertest`): engine `it` facade test about 0.1 CPU-s, osis `it` 0.3-1, a sync `it` world test 1-7, a differential seed about 9, a sim seed about 6. So each rule is tested at the lowest layer that shows it: engine facade or plain-value first, a sync world only where crossing nodes is the point.
- Demolition removes about 290 default tests and about 880 CPU-s (161 tests and 851 CPU-s match the inventory's name patterns in the baseline; `convergence::` and `sims::` are 749 of it). It leaves about 3,200 tests and 1,490 CPU-s.
- This set adds about 45 tests (40 for the properties, the differential, 5 sims) and 210 CPU-s (differential 80, sims 100, the rest 30) and deletes about 45 survivors (Old tests): about 3,200 tests and 1,690 CPU-s at the end, below the baseline with room for the lanes' own rule tests.
- The debug index check (notes/test-harnesses.md, Debug checks) is the incremental-against-from-scratch oracle of the closure structure: `Core::same_index` must compare the node closure's spanning edges and the reference index, so every test checks P5 of notes/closure-model.md for free and no separate engine P5 property is written.

## Properties
Lane: (a) refs, tickets as values, schema, API, index; (b) node root, walk, sync units, release; (c) `@` signals, inbox, tickets in sync, notices. Crate: `engine` = core/engine/tests/it, `osis` = core/osis/tests/it, `sync` = core/sync/tests/it (world tests on copied fixtures), `base`, `schema`, `vectors`.

### References and the index
| # | property (observable) | test | crate | lane |
|---|---|---|---|---|
| R1 | strong, weak and ticket encode as tags 1620-1622 and round-trip; 1616 and a ticket of any other shape or role are rejected | vectors in core/test/vectors/cbor/values.vec, one decode-rejection table | vectors, base | a |
| R2 | known references (backlinks, with kind) equal a scan of the current values of every held readable aspect: any depth, map keys, chunked values, ephemeral while held, held fires; never history, value-less writes or another actor's unreadable things | one random property: random nested writes, removes, expiry, purge, fires and arrival orders on one engine; after each commit `backlinks(t)` equals a naive walk over untyped `read`s | engine | a |
| R3 | core aspects name things by weaks (creation `admin`/`link`, roster holders, box holders, `left_out`, `reach.0`, `caps^.0`), so none of them holds anything | example: a thing's backlinks after creation and a grant list only weaks; the walk holds nothing by them | engine | a |
| R4 | a strong grants nothing and removing one revokes nothing | example: Bob writes a strong to T he has no role on: T is not fetched, reads fail with NotCarried reported; Alice removes her strong to a thing she granted Bob: his roster entry and reads stay | sync (two_nodes) | a, b |

### Sync units
| # | property | test | crate | lane |
|---|---|---|---|---|
| U1 | T's sync unit is T plus what it reaches by strongs through things its keys open; every reader computes the same; chains give the lowest role, the best chain counts | one random walk of edits (add/remove strong, grant/lower/revoke, chained grants) over 3 keyed and 4 plain things on one engine; after each, the engine's sync units equal held-model `closure::unit` on the world rebuilt from the edits | engine | b |
| U2 | NotCarried names exactly the strongs in the node closure whose target is not carried where the strong is and not held otherwise, key actors excluded; a write adding one succeeds and reports it | folded into U1: compare with the model-derived list | engine | b |
| U3 | a thing is made only where the commits of its storage transaction leave it in the node closure (`Invalid` otherwise); key actors exempt | table from `p3_making_rule`: plain under X referenced by X ok; unreferenced refused; plain from U referenced only by X refused; a key actor ok; the account's creation (P, D, profile, inbox, node thing and the node root's strong, separate commits) ok; a link's seed thing under D with D's strong ok | osis | b |
| U4 | a thing made under the account is in no sync unit and stays on its node | example: siblings; node 0 makes one under P and references it from D; node 1 never holds it | sync (siblings) | b |
| U5 | nested sharing: X granted read on Y with X -> Y -> B; a reader of X holds Y and B with no ticket for Y and syncs Y's sync ID | example (`p3_nested_sharing`) | engine | b |

### Holding
| # | property | test | crate | lane |
|---|---|---|---|---|
| H1 | a node holds exactly its node closure: root strongs, unit by unit, a keyed thing entered only by a ticket it can open or keys it holds; a sync ticket stores the unit unread and stops; a read of a thing not entered fails and nothing else changes; the walk does not enter key actors | one random property on a cached two-account LocalPeer setup: account A makes things, grants, writes strongs and tickets sealed to B inside random held aspects; every commit handed to B in a random order; B's reads (value or not-held), roster reads and sync set equal held-model `closure(Walk::Units)` | engine | b |
| H2 | the node root and its strong to D cannot be removed, nor D's strongs to the profile and inbox (`Invalid`) | table of three refused writes | osis | b |
| H3 | a strong to a thing the node never got holds nothing and reads absent, as a destroyed or released thing does (no marker) | example: the 4-event history of `p4_strong_to_never_fetched_holds_nothing` | sync (two_nodes) | b |
| H4 | cost: adding costs what it adds; removing a non-tree referrer is O(1) whatever the fan-in; removing a tree edge costs the subtree it held; a cycle is released whole | one count test at n and 10n (20/200) over the rows of notes/closure-model.md P5 counts, by `costs` counters | engine | b |

### Release and lifetime
| # | property | test | crate | lane |
|---|---|---|---|---|
| L1 | with nobody connected, a thing that left the closure is dropped at once, with its unsynced writes; it reads as not held | example on one node | engine | b |
| L2 | with peers connected, the drop waits only for the pass in flight, after which each connected peer holds what of the node's things its closure reaches; an absent peer is never waited for | two examples: connected peer wanting the thing ends holding it; partitioned peer, drop at once | sync (two_nodes) | b |
| L3 | a thing back in the closure before the pass ends is kept as it was | example | engine | b |
| L4 | a released thing is not destroyed: a concurrent re-add fetches it again, as never received | example (`p4_concurrent_readd_refetched_from_adder`) | sync (two_nodes) | b |
| L5 | the last reference gone, the thing is gone for everyone, waiting on no absent peer; the plan's Alice/Bob case: Bob's strong from B (no read on T) keeps nothing, T is gone for both; a grant to Bob or to B keeps it | one test, two arms on copies of one setup | sync (contacts) | b |
| L6 | a thing leaving a sync unit leaves its stores: each holder drops by its own view, a delete-key holder deletes, a node whose view still holds it logs it again, and everything settles | example (`p2_per_holder_delete_keeps_concurrent_readd`, `p3_unlinking_...`) | sync (three nodes) | b |
| L7 | role changes travel: revoking Z's read on T reaches a node syncing only Z and drops A (plain from T) there for good; the chain form too | the Hole's smallest history, two arms (plain, chain) | sync (three nodes) | b |
| L8 | an ephemeral strong holds while a connected peer holds the value; with nobody connected a restart drops it; once every holder restarted it is released everywhere | example (`p6_restart_drops_only_without_a_peer`) | sync (two_nodes) | b |
| L9 | lowering read to sync is no release: the thing is kept unread with its store | example | engine | b |
| L10 | a released thing's ephemeral state goes with it, the node's own ephemeral writes included; back in the closure, it is fetched again from nodes that kept it | example beside L1 | engine | b |

### Tickets and accepting
| # | property | test | crate | lane |
|---|---|---|---|---|
| T1 | a ticket lets its holder sync the target: with a strong, a read ticket reads it, a sync ticket stores it unread; one sealed to another actor opens nothing | example: ticket placed by hand in a held thing (no inbox), three arms | engine | a, b |
| T2 | nothing before the strong: an arriving ticket fetches, dials and applies nothing; accepting is writing the strong, after which it reads; declining leaves nothing | example: deliveries for the ticket's sync ID and its profile are 0 until the strong | sync (contacts) | c |
| T3 | a grant reaches its grantee as a `ticket@~0` fire; the grantee's accept reads T; the fire grants nothing (its author is the granter, verified) | example, end to end | sync (contacts) | c |
| T4 | the account's tickets: entering a keyed thing at a strong outside the local part writes D's ticket (redeem, card import, inbox accept alike), so a sibling offline past `INBOX_LIFETIME` and a node paired later enter it; releasing it removes D's ticket; a strong in the node root writes none | one test: node 0 redeems and accepts a grant while node 1 is off past `INBOX_LIFETIME`; node 1 holds both; pair node 2, it holds; node 0 releases one, D's ticket for it goes | sync (siblings) | c |
| T5 | a ticket's sync ID is its issuer's word: a forged one keeps the thing under it too, the genuine one is kept once a ticket naming it is accepted (spec/sync-hostile.md) | example | engine | c |
| T7 | a ticket enters at the lower of its role and the holder's: a read ticket whose holder was lowered to sync stores the thing unread, one whose holder was removed enters nothing | example, two arms beside T1 | engine | b |
| T6 | a key change keeps sync-only holders and holders granted again after a gap: a fresh ticket follows; a node rotating the profile or inbox, or seeing D's ticket at an old epoch, replaces D's ticket | two examples | sync (contacts), engine | c |

### Inbox and signals
| # | property | test | crate | lane |
|---|---|---|---|---|
| I1 | `@` is valid only as `@~` (never with `^` or `+`) | AK grammar table | base | c |
| I2 | anyone holding a thing's public key record fires an open signal; a writer promotes a sealed fire in place; a sealed commit with any other delta is not promoted | one world example, one plain-value promotion table beside the deposit tests | sync | c |
| I3 | a fire's delivery stays pending through a restart, is sealed again on a key change, and ends when a peer takes it | example | sync (contacts) | c |
| I4 | a removal notice fires for any change taking a reader below read; the node acts only on one that checks against its roster, releasing or keeping the retained copy; any other changes nothing | example, three arms (release, retain, forged) | sync (contacts) | c |
| I5 | an actor that is not an account is its own inbox: a grant to a team fires on the team, and its members' nodes enter the target | example | sync (contacts) | c |
| I6 | a stranded node with no writer connected fires `stranded@~0`; a writer acts on it later | rewrite of `stranded::a_holder_with_no_writer_connected_leaves_a_notice_spec_permissions_4` | sync | c |
| I7 | D's deposit seed is fresh after a device removal: the removed node's deposit to the inbox is refused (To settle) | example | sync (siblings) | c |

### Storage
| # | property | test | crate | lane |
|---|---|---|---|---|
| S1 | releasing everything returns a node to its node root, account root, profile, inbox and node things, plus the bounded rows of the plan's Storage list: nothing grows with history | one count test: from a fresh contacts world, n rounds of make, write, grant, revoke, fire, redeem, accept, decline and release; release all and advance past `INBOX_LIFETIME`, `ROLE_KEEP` and `TOMBSTONE_LIFETIME`; `disk_use(i)` rows equal at n and 10n (2 and 20 rounds) and equal a fresh world's plus the peer records | sync (growth module) | b, c |

## Differential and sim set
Replaces `convergence::` (8 tests, 389 CPU-s) and `sims::` (9 tests, 360 CPU-s).
- **World**: harness `history::world(seed, n)`, contacts made by card import (the new redeem). The existing `introduce`/`accept` helpers are rewritten: `accept` becomes a step, not something every step does.
- **Steps generated**: `New` (under a held thing, its first admin), `Strong`/`Unstrong` (any known tid, readable or not), `Write`, `Grant` (sync/read/write to an account or a thing, so chains occur), `Lower`/`Revoke`, `Rotate`, `Accept` (a strong in D or a held thing to a ticket's target), `Decline` (nothing), `Pair` (rare), plus the existing partition, heal, restart, power-off and loss steps.
- **Oracle, from the history only**: final world for held-model: kinds (a first grant gives own keys; plain things derive from their maker), grants (last role commit per (actor, thing)), edges (the reference engine's current values); per node a `NodeView`: roots are its node root's strongs, tickets are those sealed to its account in data its closure holds (fixpoint from empty: the closure only grows with tickets), Open where the account's role at the end is read or above, SyncOnly where it is sync (whatever the ticket's role, spec/sync-set.md §2); D entered by keys. Tickets in D come from the account's-tickets rule (spec/sync-set.md §1): a ticket for each keyed thing any node of the account entered at a strong outside its local part and has not released.
- **Excuse, from the history only**: (account H, thing T) may fail to read T's content at quiet exactly when the history has a rotation of T's read role made by a node that had not received H's last grant on T, that grant made by a node that had not received the rotation (spec/permissions.md §3 Left out), and no node up at quiet belongs to an account that holds write or above with key access on T at the end and that the rotation boxed (its maker's account and the holders it knew). The excuse permits a failure, never requires one: an orphaned epoch rotated at a later write heals it too. Received is the harness's delivery relation (partitions and heals), never the node's state.
- **Compared at quiet**: per node and thing, read succeeds iff the model holds it read, and then value and roster equal the reference engine's; sync set equals the model's read and stored keyed things (plus link and destroyed sync IDs, taken from the history); no store entry of a sync ID outside it; the existing no-read-without-grant clause; quiet is reached within `STORM_CAP` (no two nodes undo each other).
- **Size knob**: one function. Small (gate): 3 nodes, 2 accounts, 30 steps, 10 seeds, every second faulted. Large (`OSIS_FULL=1`): 4 nodes, 3 accounts, 60 steps, 100 seeds. Cost grows with steps times nodes squared; the model is pure and cheap. One test, named histories_hold_their_closure.
- **Sims** (each 4 seeds small, 40 large, same oracle plus its stated outcome): a reader through a node keeping it unread (sync-only ticket), crashes and restarts in place (ephemeral strongs, pending fires), lost and repeated messages, a peer refusing role entries (role changes travel), store failures. The old full-peer, held-open and lying-in-own-log scenarios fold into these as fault weights; skewed clocks into the differential's faulted seeds.

## Old tests
Survivors this set makes redundant, to delete once it lands (name per module; where demolition already deletes one, nothing to do):
- osis `references::{rows_follow_the_values, rows_follow_the_value_in_any_arrival_order, rows_survive_what_their_states_survive, an_expiry_and_a_purge_remove_rows}`, `backlinks::{a_reference_shows_and_stops_showing, backlinks_follow_writes_in_any_arrival_order, live_through_add_remove_expiry_purge, only_what_the_actor_may_read}`; engine lib `engine::refs::tests::tids_at_any_depth`: R2. Keep `references::a_path_write_costs_what_it_writes`, `backlinks::paged_at_n_and_10n`, `backlinks::a_validity_flip_reaches_backlinks_and_listeners_spec_permissions_5_1`.
- sync `leave::{nothing_leaves_before_the_synced_group_is_known, unshared_stops_at_once, an_unsync_ends_a_wait_for_lists, unsynced_stays_synced_until_own_writes_are_elsewhere}`: L1, L2. The other nine `leave::` tests are the release timing rule, renamed.
- sync `destruction::{a_node_alone_forgets_a_released_things_sync_id, a_released_thing_reads_absent_and_its_sync_id_is_forgotten}`: L1.
- sync `siblings::{a_sync_grant_accepted_on_one_sibling_is_kept_at_both_spec_sync_3, a_sibling_paired_after_inbox_lifetime_keeps_an_accepted_grant_spec_sync_3, a_rotation_reaches_kept_siblings_without_an_accept_spec_sync_3, unsyncing_on_one_sibling_leaves_the_other_its_copy_spec_sync_set_3}`: T4, T6.
- sync `links::{a_held_join_forgets_the_link_and_k_syncs_by_its_filing_spec_permissions_7, a_siblings_join_ends_a_redeem_spec_permissions_7}`: T4.
- osis `sync::{a_thing_listed_nowhere_stays_on_its_node_spec_sync_set_2, a_shared_thing_syncs_at_the_sharing_node_spec_sync_set_2, a_link_to_a_thing_listed_nowhere_is_served_spec_sync_set_2, a_thing_whose_share_ended_is_kept_until_unsynced_spec_sync_set_3, an_unsynced_thing_is_forgotten_here_spec_sync_set_3, an_unsynced_thing_no_peer_shares_goes_at_once_spec_sync_set_3, an_unsynced_write_goes_out_before_the_copy_goes_spec_sync_set_3, redeeming_a_link_joins_and_files_its_thing_spec_sync_set_4, importing_a_card_gives_the_account_spec_sync_inbox_5, the_contact_card_is_a_read_link_to_the_profile_spec_sync_inbox_5, a_paired_node_knows_the_accounts_profile_spec_sync_set_1, a_write_reaches_the_accounts_other_node_spec_sync_set_1, a_third_accounts_node_relays_a_group_it_keeps_unread_spec_sync_3, accepting_into_a_group_not_synced_is_invalid_spec_sync_set_4, an_unsynced_invitation_is_acted_on_spec_sync_set_4}`: U3, U4, L1, L2, T4, the sims.
- engine `facade::` sync-set and kept tests not named by the inventory: `a_grant_shares_its_thing_at_the_granting_node_spec_sync_set_2`, `a_grant_to_a_node_shares_nothing_spec_sync_set_2`, `a_grantee_leaving_ends_the_share_spec_sync_set_2`, `a_share_is_the_accounts_and_ends_with_its_grant_spec_sync_set_2`, `a_shared_thing_lost_is_shared_no_more_spec_sync_set_2`, `unsync_ends_a_share_until_a_new_grant_spec_sync_set_2`, `sharing_one_more_thing_walks_the_closure_once_spec_sync_set_2`, `marking_an_add_costs_its_size_spec_sync_set_2`, `the_sync_set_rows_name_every_sync_id_entering_spec_sync_set_2`, `forget_local_*_spec_sync_set_3` (4), and the `_spec_sync_3` accept/offer/forger tests (`a_forgers_earlier_accept_*`, `an_accept_keeps_the_offered_sync_id_*`, `an_accept_with_a_forgers_offer_held_*`, `an_offer_after_the_accept_attaches_nothing_*`, `a_thing_accepted_under_a_sync_id_tied_to_another_*`): U1, H1, H4, T5.
- held-model `spec_closure`: all 24 stay (0.8 s): they are the oracle's self-checks.

## Order
The foundation commit is not on main yet; check signatures once it lands.
- **Now, before any lane**: the differential's oracle adapter (history to held-model `World`, `Edges`, `NodeView`, with the ticket fixpoint) and the new `Step` variants, as pure code in the sync harness; the S1 skeleton (rounds, `disk_use` counts) on today's harness.
- **After (a)**: R1, R2, R3, I1 (if the AK parser is lane a's).
- **After (b)** on (a): U1-U5, H1-H4, L1, L3, L9, T1 (tickets placed by hand), T7, T5's engine part; then, once sync carries by sync units, R4, L2, L4-L8.
- **After (c)**: T2-T4, T6, I2-I7.
- **Last**: S1 run for real, the differential and the sims; then delete the Old tests and measure with `tools/pertest.py compare`.
