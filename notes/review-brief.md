# Review brief: everything since the sync rewrite
> Summary: Working note for the one big review and gate over main since the sync rewrite (e8f9ae5d4, about 270 commits to dd5c0a3e4): three review areas with their oracles and main rules, every ruling flagged for review (checked against main), the baseline failures on main (gate selection and the full-size sync differential), and the gate's cost. Delete after the review.

Range: `git diff e8f9ae5d4^ origin/main` (the squashed rewrite plus accounts as ordinary things, public things and cards, copies cut per sync ID, per-holder pieces and follow-ups). Line counts below are changed lines (added + removed) in that range.

## Areas
Each reviewer judges code, spec and notes against the abstract model and the oracle (notes/principles.md; memory: model first), and reads the rulings of its area below.

**(a) Permissions, keys, rotation** (product about 10k lines; rotation tests 7.8k, roles-model 5k, TLA 4k)
- Files: core/perm/, core/keys/, core/crypto/, core/engine/src/rotation/, apply/{keys,validity,paths,waits,reach}.rs, engine/secrets.rs, engine/sides.rs; the wire-level crates the per-holder pieces and page links touched (core/base, commit, blob, proto, crdt paging).
- Oracle: spec/permissions.md §1-3, §5 (Path, The public, Granting to a thing / the public, Required rotation, Holder actors, Role cycles, Re-seal, Lost access; Passes, Lowering, Trust set, Sides, External fires); spec/crypto.md §3 (Independent thing, Published KEM keys, Read key in force), §4 (epochs, boxes, floors, departures, Holder actors: Key access, Foreign, Seal, Stale, Left out, Carried demotions, Destroyed), §5 Who wraps under what, §7 Delete keys; spec/commits.md §4 (Unjudgeable, Delete keys, overlapping counters); spec/wire.md §7. Notes: holder-actors, keys*, key-access, delete-keys, disputes, perm-paths, permissions, engine-roles, engine-validity. Models: core/test/tla/rotation (Rotation, Depth0, Joint, LeftOut, ForkRot, ForkDepth, KemKeys, FireKey, Cut, Cover, Tail, Withdrawn, Planted, Reseal), tla/sides, roles-model (`paths`, `proofs`, `purge`, `leave`, `told`), held-model key checks (`miskeyed`, `independent`, `box_cut`), engine `rotation::tests_property`.
- Rules built: validity along stated paths (role timeline, drop sets, void lowerings, re-grant); disputes by trust set, held first, permanent forks; required rotation on departure, none on self-removal; epochs established/current, encrypt only under one covering every known departure; holder actors at depth 0 (Seal at anchors, joint boxes, stale boxes by box records, left out with causes then re-key, carried demotions, destroyed holders); keyless grants give no secrets; checked delete keys (levels 1 and 3 placed by a recorded step; first steps and `created.0` excepted); granter's check and KEM key due; the public's role and open boxes.

**(b) Sync** (product about 10.5k lines; osis-sync tests 5.4k)
- Files: core/sync/src (opens, streams, read, status, inbox, store, driver, session, leave, unread), core/engine/src/sync/ but certblobs.rs, certified.rs, pieces.rs; core/engine/src/sync_ids/ but certs.rs; core/store, core/transport.
- Oracle: spec/sync.md; spec/sync-set.md §1-5 (node thing and root, dial list, sync units, First entry, held for keys, Release); spec/sync-ids.md §1-6 (steps and claim sets with the public entry, `sync.0`, store operations, certificate blobs); spec/sync-opens.md §1-6 (proofs, records, shared set J, Departed, filters, Ending); spec/sync-streams.md; spec/sync-judgement.md §1-6; spec/sync-status.md §1-3; spec/sync-inbox.md §1-6; spec/sync-compaction.md; spec/sync-hostile.md §1-2. Notes: sync*.md, holder-access-study, node-closure. Models: core/test/tla/net (NetStream, NetShared, NetOpen, NetHold, NetKeep), tla/sync SyncConvergence, held-model `closure::entry`/`public`/`cards`, roles-model `told`/`leave`, the sync differential and sims (core/sync/tests/it); rules no model checks: issues/sync-models-lag.md.
- Rules built: a sync unit is the readable closure, first entry by founded edge pieces of own/read/link things or an offer; held for keys walking up from the closure; judgement per sync ID (required set, must/may/must-not, logged again once, kept unread); opens on each side's own judgement of the peer's proof now, departed members ended and served role entries alone; one connection and record per pair; stores keeping S unread (walk, stops, Register); held elsewhere for a self-removal; inbox deposits, grant fires and offers, sealed copies never promoted; the public entry and public pieces; streams (node log, cursors, `Lost`, stall rule).

**(c) Evidence, certificates, retention, closure, accounts, public and cards, API** (product about 13.5k lines; held-model 7.3k)
- Files: core/engine/src/evidence/, retention/, flows/ (inbox, offers, cards, links, edges, addenda, sync_ids, create, roots), engine/ (core state, held, acting, write, read), apply/ other than (a)'s, sync/{certblobs,certified,pieces}.rs, sync_ids/certs.rs, local_peer.rs; core/osis/src; libs/account; schema/realm.osis; libs/kit and app for the one-home change.
- Oracle: spec/permissions.md §4 (Evidence, Key part, Copies, Logging certificates, Delivering an edge piece, Stranded), §7 Links, §8 Accounts; spec/commits.md §4 (Pending storage, Records, Outside the node closure), §5 (retention: One way, Covered, Forgetting, What a held thing needs, Keep bounds, Purge, Destruction), §6-7; spec/sync-set.md §1-2 (counts as independent, T's keys open, Stub, Public pieces, Own things); spec/sync-inbox.md §1 card, §5 offers, §6; spec/data-model.md §8-9 (`card.0`, `dial.0`, `caps^.0`); spec/wire.md §4, §9, §10. Notes: certificates, evidence-derivation, closure-model, node-closure, stubs, engine-retention*, addenda, links, realms, api, api-design, history-less-grant, accounts-switch-brief, public-and-cards-brief. Models: held-model `evidence`, `closure` (`entry`, `cards`, `public`, `keys`), `copy_cut`, `thing_history`; the sync differential uses held-model closure as reference.
- Rules built: evidence of a commit (E1 plus steps placing its listed keys), derived per sync ID; copies cut per (commit, thing, sync ID), `secrets.0` in pieces judged alone, the rest piece only to a holder reading X; delivery to a holder (grant fire or offer on the card's inbox; rotations as sealed copies; nothing to the public); counts as independent by role commits or a box whose step bears its sync key; certificates outside the closure kept while needed, dropped at a pass end; retention setting judged order-independently; cards (`card.0` along a path through A, inbox by greatest `since`, refreshed by writers); accounts (make, pair by keys/grant/offer/`take_offer`, removal by `set_role` and a Write; home is the account, realms schema only).

## Rulings to check
One line each: the ruling, its state on main (dd5c0a3e4), where to look. "Applies" means the code still does what the ruling says; the reviewer judges whether it should.

**(a) Permissions, keys, rotation** (15)
- `created.0` excepted from every verdict on its commit, key placement and the overlapping-counter void alike (a record hashes to its tid and needs no authority, spec/permissions.md §1): done (spar-review-tidy). Engine `Judge::part` takes `created.0` before `ix.void`, `apply::unjudgeable` excepts it from `miskeyed`, as held-model does; spec/commits.md §4 names both exceptions; engine `validity::a_void_minting_still_creates_spec_commits_4`.
- Granter's check "may write H or holds H's current `keys.0`" (strict card rule would remove a user capability): applies. Done (spar-review-tidy): "current" is the newest this node holds, which is what the code reads (no node can check against one it lacks; a removed reader holds H's newest too); spec and `grant_holder` say so; `rotation::tests_kem::a_reader_holding_the_holders_current_keys_grants_*`.
- The public's role counts wherever its grant is held, not only on synced things (dd55273fe): applies, worded as an exception in spec/sync-set.md §2 Own things. `rotation/lost.rs` `role_here`.
- Dependent-box: an admin's step+box with no keyset, admin then demoted, leaves the boxed reader counting the thing independent: applies; only a code comment calls it an admin dispute, and only demotion before the plant is tested (`tests_planted::a_demoted_admins_step_splits_nobody_spec_sync_set_2`). `engine/secrets.rs` `own_record`/`stepped`.
- Left-out causes: a removal rotating in the same commit stands as a rotation (a regrant costs one re-key): applies. `rotation/members.rs` `stands`; spec/crypto.md §4 Left out; LeftOut.tla `LO_rot`.
- Foreign epochs at depth, as reworked by its reviewer: applies. spec/crypto.md §4 Foreign; `rotation::members::Foreign`, `tests_foreign.rs`; ForkDepth.tla `FD_race*`, `FD_fork*`.
- Permanent fork: a stranger delivering one side's commit first picks the receiver's side (held first): applies, accepted by Tess. notes/disputes.md; spec/permissions.md §5.1 Sides; `engine/sides.rs`.
- A miskeyed part never drops as invalid (a writer listing made-up keys leaves parts unapplied for good): applies. `sync_ids/steps.rs` `wrong_keys`/`rekey`; spec/commits.md §4 Pending storage.
- Remover sealing to an ignorant fork (Tess accepted); the names-digest check unstudied: applies. notes/holder-actors.md, Judged by order where the secret is lacking.
- Destroyed holder actor: a timed edge past its `until` stays a frozen holder: applies. `Core::key_holders`/`expand_destroyed`.
- Box records: an admin snapshot covering one drops it ("not defended"); per-unit cost a tess-call: applies. issues/account-evidence-per-unit.md.
- A left-out cause later invalidated keeps M out until one re-key; invalidators voided in turn unmodelled: applies. Tail.tla `T_chain`.
- A wrong-form box to the public counts as present for the re-seal trigger: applies. `osis_keys::covers::reseal_missing`.
- Seal skipping KEM-less keysets has no test of its own; a removal's own rotation may write a KEM-less keyset, fixed by KEM key due next pass: applies. `rotation/kem.rs`; KemKeys.tla `KK_fallback`.
- Link keys keep seed-derived secrets and the static entry, "the one special case" (source calls it a smell): applies. notes/accounts-switch-brief.md, Decisions and why.

**Findings (a)** (spar-review-a). Rulings, in order:
1. `created.0` excepted: agree. Its exception in `apply::unjudgeable` is dead (the one caller checks `!valid_at` first; `created.0` is always valid) but harmless. The key-placement half had no test: `validity::a_minting_listing_unplaced_keys_still_creates_spec_crypto_7` (ae9708ca4, fails with the exception moved below `miskeyed`).
2. Granter's check: agree.
3. The public's role wherever held: agree (the public is every party). Unproven caveat: `role_here` feeds `may_take`/`readable` for the node's own sealed boxes too, so a public grant whose removal the node lacks could keep a removed reader's sealed secrets; a role through the public giving only open boxes would make the ruling harmless.
4. Dependent-box: demotion after the plant behaves as the spec says (the `sync.0` write judged at its point stays valid). Open: no rule reconciles boxed and unboxed nodes (the planted epochs are never established, so nothing re-seals); untested.
5. Left-out causes: agree (LO_rot). No test fails if the edge check runs before `writes_keyset`.
6. Foreign at depth: agree on finding, anchoring, sealing, superseding. Re-key may repeat: reproduced (one extra re-key of the holder actor and one of the thing above) and fixed in spar-fix-rotation (`rekey_due` and `left_out` read the node's view of the holder actor; test `a_foreign_keyset_left_out_is_rekeyed_once_spec_crypto_4`, ForkDepth `FD_race_u_rekeylists`). `Foreign`'s doc wrongly said no writer can make a node's own keyset foreign (f88ffb28c).
7. Permanent fork, held first: agree.
8. Miskeyed never invalid: agree in validity, but the sync judgement judged such bodies invalid and unlogged them: fixed ae9708ca4 (`sync/bodies.rs`, test `validity::a_body_listing_an_unplaced_key_is_not_judged_invalid_spec_commits_4`). Held outside Pending storage, unbounded: fixed (spar-fix-security: a received miskeyed part is unjudgeable in `examine`, `Reason::Miskeyed`, woken by `Wake::Steps`; test `validity::miskeyed_writes_pend_and_go_with_their_entries_spec_commits_4`).
9. Remover sealing to an ignorant fork: agree (accepted). The names-digest option proves knowing only on a match with the departure, ignorance only on a match without; any other set the rotator held matches neither and proves nothing.
10. Destroyed holder with a passed `until`: applies as spec'd; the spec rule over-extends a timed grant: issues/destroyed-holder-timed-edge.md (judge `until` at the destruction point, no clock read).
11. Box records dropped by an admin snapshot: agree (hostile admins not defended).
12. Invalidated left-out cause: agree (`left_out_on_an_invalidated_rotation_ends_with_one_rekey`).
13. Wrong-form box to the public: spec says ignored, the trigger counts it present: fixed in spar-fix-rotation (`osis_keys::has_box`).
14. Seal skipping KEM-less keysets: agree; still no test of its own (extend `tests_kem::kem_key_due_ends_a_lockout`: before KEM key due, a rotation leaves M out, never seals at the older keyset).
15. Link keys: agree. Justified by the link requirement (a bearer secret opens K with nothing else) and the record being the one origin fact; the seed-derived first secrets are the mint-with-key rotation with fixed randomness.

Other findings:
- Spec: Encrypting under excepted "an own thing's" departure; a link key's other redeemers hold its keys, so only the node thing's (as the code does). Crypto §4 Reading-only kept a box the node's roles do not give "for reading"; permissions §3 and the code take nothing. Both fixed in f88ffb28c, with comment remnants of the removed account machinery.
- `rotation::walk_from` past an epoch whose secret is lacking followed boxes to the node thing (a remnant of the removed account machinery): deleted in spar-fix-rotation.
- Sides: the spec's own-lowering-trusted clause and "no order, no side": built in spar-fix-rotation (`sides::after_update`); the writer's check still refuses a removed admin's counter-removal (notes/perm-paths.md, Read short of the spec).
- Low, no issue: a step's `since` (`sync_ids::steps` `Recorded::of`) is the current write's stamp, so an admin re-putting a step entry later makes commits stamped in between miskeyed for good (hostile admin only).
- For (c): the Interim on `apply::header_wait` (apply/mod.rs ~913) says it waits for every listed thing's record, which is what the spec wants; `thing_wait` already does so per part. Recheck what issues/stated-path-certificates.md still owes.

**(b) Sync** (20)
- Removal-told metadata (count, size, timing of later sealed role entries) shown to a departed node in two timing cases (newest superseded epoch past the removal; no `until` before the rotation is logged): applies; stated in spec/sync-hostile.md §2 (done, spar-review-tidy) and notes/sync-opens.md (Departed peers). `opens/holds.rs` `departure_until`, `opens/mod.rs` `close_if_reached`; spec/sync-opens.md §6.
- `sync.0` is a role part; a floored holder sees steps below its floor; any holder encrypts a `sync.0` part under a roles secret it holds: applies. spec/sync-ids.md §4-5.
- Held for keys walks up from every thing the closure holds (unread ones too), every hop with key access, only while a read secret is held: applies; the multi-hop case has no test (issues/roles-apart-from-syncing.md). `sync/units.rs`, `retention/needed.rs`.
- A holder held for keys is a source class, not a `Pull` selector: applies. notes/sync.md, Held for keys; `streams/pull.rs`, `relay.rs`.
- `deliver_copy` fires by the writing node's role on the holder; a writer of H not syncing H logs and fires nothing: applies. `flows/inbox.rs` `deliver_copy`.
- An offer is all a node knows of a thing it does not sync (`role_on`); an ended grant whose removal fire never arrives is never corrected: applies (accepted gap). `Engine::role_on`, `rotation::lost::grants_count`.
- An arrival no pass brought waits in `Core::pass_due` for the next pass end: applies. `retention/needed.rs`.
- Copies keyed per thing: a record reaches a reader only by the record rule or the account's public record; source of the 8 "copies per (commit, thing)" ignores: applies. `sync/certblobs.rs` `minting_opens`, `sync_ids/certs.rs` `current_keys`.
- Three test rulings (`pieces::a_small_edit_*` and `growth::several_writers_grow_nothing_*` assert results not order; `keep::a_head_move_restamps_*` skips node 2's deposit by `blob_loses`; `parts::` harness takes `order::judge_at`'s node): apply. osis-sync `it`.
- Member `standing` memo keyed (record, S), not rejudged when the connection's copies change: applies. `opens/holds.rs` `standing`.
- Held elsewhere for a self-removal: filtered through `counts_for_leave` (resolved), but `g.elsewhere(s, b)` returns Yes before the filter: check whether a leaving peer can set it. `status/mod.rs` ~l.1020-1050. `counts_for_leave` reads the proven node alone, not each claimed thing's role: applies. `engine/src/sync/held.rs`.
- A new strong to an uncarried thing re-pulls every own and read sync ID (`units::refetch_holders`): applies (stated cost).
- The new node's first dial: pairer's `dial_hints` not stored, a restart before A's `dial.0` loses them: fixed (spar-fix-sync): the `Offer` names the pairer's peers, kept as a joined link's (`Node::offered`); the osis dial hints call gone.
- A public redeem is in memory only: applies. osis-sync `inbox/links.rs` `redeem_public`.
- A stranger's sealed fire to an inbox kept unread then promoted: untested (issues/sync-tests-owed.md).
- `SETTLE_MS` designed, not built: every holder copies a demotion or `keys.0` at once (3.3 KB per holder per removal). issues/sync-unbuilt.md, Cost.
- A record flood evicts records least recently used (a few 5 MB filters evict all): applies (accepted). spec/sync-hostile.md §2.
- Not built: static entries claimed in the walk's tests (`Tested::Static`), rejudging connections on a policy change. issues/sync-unbuilt.md, Opens.
- notes/holder-actors.md on logging and `Walk::Log`, and stranded reports: fixed (spar-review-tidy): logging reads the walk in `Engine::wrap_blocked`; stranded reports built.
- Next/Untested in notes/sync-rewrite-state.md: own boxes only for a holder held for keys, acting only after a complete pass, a paged role commit as evidence, a sealed copy stamped ahead of the receiver's clock, a sealed fire opening pending for drift: open.

**Findings (b)** (spar-review-b). Reviewed main through 4ff1c3a9f (spar-lapsed-rotation landed: its `Conn::served` guard applies only to walk Hits on superseded or lapsed secrets, so a current read secret is never refused by it; spar-kept-unread not landed during the review). Rulings, in order:
1. Removal-told metadata: agree (stated limit, sync-hostile §2).
2. `sync.0` a role part: agree.
3. Held for keys from every held thing: agree; multi-hop still untested (issues/roles-apart-from-syncing.md).
4. Held for keys a source class: agree (the class reaches every rule reading a source before any Pull).
5. `deliver_copy` by the writing node's role: agree; the spec states the gap (no node holding a piece syncs H), and a writer of H normally has H in its closure.
6. An offer all a node knows of an unsynced thing: agree (accepted).
7. `pass_due` waits for the next pass end: agree (storage only; what a hand-taken `Keys` brings waits there too).
8. Copies keyed per thing: agree as (c) found.
9. Three test rulings: not checked.
10. `standing` memo keyed (record, S): agree; a resumed record re-judges nothing unchanged (spec/sync-opens.md §6), and the old copies are verified evidence; a removal held moves the memo.
11. Held elsewhere for a self-removal: agree. A self-removal is in `held_wait` from the transaction that applies it, and its blobs are marked `elsewhere` only through `held_at` for that commit, after `counts_for`; `role_now` is the effective role, so a node of another account counts through its account where its roster is held.
12. `refetch_holders` re-pulls: agree (stated cost).
13. Dial hints not stored; 14. public redeem in memory: fixed (spar-fix-sync): a public redeem is a durable `I/r/` row as a share link's; an offer's peers kept as a joined link's.
15-19. Sealed fire kept unread then promoted untested, `SETTLE_MS` unbuilt, record flood, unbuilt opens rules, Next/Untested: agree, as listed.
20. holder-actors logging fixed: agree.

Reviewer (c)'s two observations:
- `wait_synced(All)` never resolving after a self-removal: as spec'd. After b leaves, the pairer has no connection (it dials nobody; only b dialed in), and the account's profile is public, so "some other node may hold it" holds for good: a node alone never waits out a public thing (sync-status §3). Waits on the account and the node thing resolve.
- An outside node's `take_keys` of an account's keys left no current keys: a bug, fixed (6310c22f6). `take_holder_keys` judged commits before the chain stood (the account's record names its mint admin, the node, whose record came later in the same loop, so the keys commit pended on a record that was there and was dropped), and it took `sync.0` only on the holder, so the signer's step placing the keys the commit lists was refused and the commit stayed miskeyed. Spec wire §9 and permissions §4 now say `sync.0` on chain things.

Other findings:
- `wait_synced(All)` does not wait for sealed fires owed, which spec/sync-status.md §3 requires (the line also names a removed "deliveries" scope): fixed (spar-fix-sync): `Node::wait` on all stays pending while `Engine::delivering`.
- Held elsewhere trusts a reader's reported position, which notes/sync-status.md accepts; it is a peer's word, as a stream's presence is: no different in kind, not filed.

**(c) Evidence, certificates, retention, accounts, public, cards, API** (17)
- One value for an edge piece from outside (`EdgePiece`), one taker for fire and offer: changed by dd5c0a3e4 (a grant fire cut to its one holder, offer trust records cut to evidence). `flows/inbox.rs` `take_edge_piece`, `flows/offers.rs`, `Engine::edge_piece(Cut)`.
- A sealed copy is never promoted (taken whole as a sealed fire's commit): applies. `inbox::open_sealed_fire`, `deliver_sealed`.
- `card.0` never compacted, so a reader floored after a card was written (a history-less joiner) sees it only once rewritten: applies; the source calls it a smell. `retention/snapshot.rs`, `compact.rs`; spec/commits.md §5.
- A card's keys mostly repeat the fellow-holder rule; its own work is the inbox, `since` and KEM keys (source raises it): applies. `flows/cards.rs`.
- Copies holding more than S's cut stay in stores (storage; a part once in S's cut stays readable to later readers): applies. osis-sync `read/judge.rs` `unnamed_copy`, `facts::body_held_by`; notes/sync-rewrite-state.md, Next ("A copy's parts as exactly what S names").
- notes/certificates.md (The cut, Pieces): fixed (spar-review-tidy): the rest goes only to a holder reading X, in every carrier (`cut_parts`).
- Home is the account itself (Tess: "suspicious but fine"): applies (864c0c8da). notes/realms.md.
- `dial.0` keyed by node thing (`{key, urls}`), `refresh_reach` writes it: changed from the brief. spec/sync-set.md §1 Dial list.
- Pairing hands the offer over the channel (keys, grant, offer, `take_offer`), no `grant@~0`: applies. `osis/src/share.rs`, `flows/offers.rs`.
- Stubs widened to sync; first entry only by own and read things' key parts: applies. spec/sync-set.md §2 Stub, First entry.
- Node settings as each node's entry keyed by node thing (`caps^.0`); `clients^.0` on the node root is a tess-call: applies. issues/settings.md.
- Where the node thing's secrets live when its key store is copied: open tess-call. issues/recovery-design.md.
- `leave` keeps link keys; link commands on a lone node run to their timeout; stolen-node steps 4 and 10-14 untested: applies.
- Interim in `osis/src/disputes.rs` ("no dispute over a key's grant"): repointed at issues/key-grant-disputes-unlisted.md (low; the API names no key holders; only a hand-written `signers.0` removal makes one) (spar-review-tidy).
- Accepted risks: things minted with admin A are dependents; node things show to every reader; A's tid on every path; a strong to a public thing copies it under every referrer's unit; stores learn a unit is public; a stale card seals to A's older keysets (a party removed from A may open). notes/accounts-switch-brief.md and notes/public-and-cards-brief.md, Risks.
- Revocation reach eventual; record chain depth capped at `MAX_CHAIN_DEPTH` 64: applies.
- `Need::Acting` (`Indexes::by_actor`) is Interim: applies. issues/stated-path-certificates.md.

**Findings (c)** (spar-review-c). Rulings, in order:
1. One `EdgePiece`, one taker; a grant fire cut to its holder: agree. Left: sync copies are unbuilt in every carrier but `edge_pieces_into`: a fire, sealed copy or offer to a holder of sync alone carries its whole piece with evidence (its readers learn X's roster and paths), and a stub's pieces are cut by each holder's role, not the unit's; the spec's Stub and Carriers lines disagree (issues/account-evidence-per-unit.md).
2. Sealed copy never promoted: agree.
3. `card.0` never compacted: not acceptable. It contradicts spec/crypto.md §4 State at a cut (each aspect's state reaches a floored reader as a snapshot), and no cover ever drops a replaced card write, so card history grows with every rotation of its thing. Fixed (spar-fix-compaction): one card aspect per thing, `:<A>:card.0`, its writes and snapshots judged by one rule (a card counts only along a path through A), retained, snapshotted and covered as any content aspect. The same gap, undesigned: no role-class snapshot is written at all, so replaced `keys.0`/`secrets.0`/`sync.0` bodies stay for good though the spec allows covering them. Fixed (spar-fix-compaction): an admin's trigger compacts `keys.0`, `secrets.0` and `sync.0`, and replaced parts of role commits drop past `ROLE_KEEP`; live role-class parts stay for good, so rotations still grow stores (issues/role-class-live-bodies-kept.md).
4. A card's keys repeat the fellow-holder rule: agree (they are a stranger's only route; the cost is one card per host). Found: a card's `since` was the writer's word, so any writer of A (a realm member with write) could pin A's inbox to a thing it controls past its own removal, and A's nodes copied it to every card. Fixed (35d5f7cdf): a card whose `since` is past its write's `ts` is invalid (parking bounds `ts`), `write_card` runs its clock ahead to a move's `since`; spec sync-inbox §1, data-model §9. Open (design, not a bug): any writer of A may still move A's inbox (a writer's power; for a realm that is every write member).
5. Copies holding more than S's cut stay: agree (storage; the extra parts were readable to S's readers when logged).
6. notes/certificates.md cut in every carrier: agree for the reading-holder rest; see 1 for sync alone.
7. Home is the account: agree.
8. `dial.0` keyed by node thing: agree. Found in `remove_node`: the role went before the entries, so a node removing itself failed with `Permission` after losing its role, and a retry returned at once, leaving the dial and caps entries for good. Fixed (d27efc3f9).
9. Pairing hands the offer over the channel: agree (the offer text is the root of trust; a removed admin node not yet told can still pair, as spec'd). Found: `take_offer` took an offer only where the node thing itself held the grant, so an offer to an account was refused at its nodes after `Osis::offer` had dropped the fire. Fixed (7c367a7a2): a node of the holder (the node thing or a thing it may write) takes it, as `offered_to` reads a fire. Not fixed, suspect: `take_offer` ingests the offer's records and commits before refusing (storage until the pass ends, if released at all).
10. Stubs widened to sync; first entry by own and read things' key parts: applies as it stands (in the kept-unread rework); see 1 for the stub cut.
11. `caps^.0` per node, `clients^.0` a tess-call: agree.
12. Node thing's secrets when the key store is copied: open tess-call, agree.
13. `leave` keeps link keys; link commands on a lone node time out; stolen-node steps untested: applies (`remove_node` returns the links still working; not checked further).
14. Interim in `osis/src/disputes.rs`: agree (issue open, unbuilt).
15. Accepted risks: agree; a writer's inbox redirect is now undone by any later move (4).
16. Revocation reach eventual; `MAX_CHAIN_DEPTH` 64: agree.
17. `Need::Acting` Interim: agree. For well-formed paths the hops already keep every member needed (each hop is a record edge or a held edge write naming the previous member); what replaces it is the spec's "every listed thing". (a)'s note: `header_wait`'s mark described the spec, not the code; rewritten (380343fde), and issues/stated-path-certificates.md now says what waits where. Suspect, in that issue: a hop to a listed thing whose record is unknown waits as `MissingChain(signer)`, which the record arriving does not wake.

Other findings:
- Removed node acting through a client's thing it administers (`add_client` minted with admin N): fixed (spar-fix-security: `add_client(admin, until)`, the account its admin; test osis-account `a_removed_node_no_longer_acts_through_its_client_spec_permissions_8`).
- Remnants of the removed account machinery: gone from code, tests and notes, refused by `tools/policy.py` `DEAD_WORDS`; API terms settled (notes/terms.md, API words). Stale "take it after A5" lines dropped from issues/sync-link-first-contact.md and links-as-offers.md.
- Evidence derivation reads parts from headers, not holds: a dropped part's path stays in S's evidence while its header is held (issues/engine-evidence-trails-model.md, The derivation's input).
- Seen, not followed (area (b)): in osis-account's test of a node removing itself, the other node's `wait_synced` never resolved after the self-removal (erase by default), and an outside node's `take_holder_keys` of an account's `holder_keys` left no current keys (`current_keys` empty). Both worth a look by whoever owns sync and keys.
- Suspect, no issue: `Account::nodes` lists every write or admin holder of A (a client's thing, a realm) as a node; a removed node keeps `settings^.0` naming A, so `Account::of` says it still acts for A.

**Security-tagged issues** (27 open; by area, one line each)
- (a) issues/removed-node-reads-later-grants.md (normal, tess-call: rewritten (spar-review-tidy): A5 closes nothing; the deposit seed is no leak of its own; the wrap's fix or a weaker property is Tess's); issues/demoted-writer-deletes-at-stores.md (normal; "option 1 if easy", unbuilt; level 2 still `RoleKey::Sync`); issues/maker-unknown-from-snapshot.md; issues/unvouched-read-keyset-stalls-fires.md; issues/perm-hostile-path-joins-components.md (cost); issues/history-less-grant.md ("from now through holders" unbuilt).
- (b) issues/stranger-fire-bounds.md (normal; was waiting on A5, now unblocked); issues/removed-key-writes-show-far.md (normal, decided not to build around); issues/engine-invariant-wedges-sync.md (normal); issues/cert-blob-hostile-delete.md; issues/dial-candidates.md; issues/sync-memory-uncounted.md; issues/sync-units-linked-at-rest.md; issues/resource-limits.md; issues/privacy.md; issues/p2p-own.md.
- (c) issues/backdated-replace-cuts-history.md (spec wording still "erases nothing"); issues/purge-floor-exact-ts-ties.md; issues/revoke-link-before-its-seed.md; issues/forged-copy-undetected.md; issues/durable-decode-bound.md; issues/eph-node-cost-bounds.md; issues/client-auth.md; issues/cli-proxy.md; issues/root-key-erasure-tier.md.
- The issue on external signals taken by default: closed (spar-review-tidy); what is left is issues/held-set-external-fires.md.

**Landed unreviewed, for the final review**: f4acee5a2 (a holder deletes a sealed sync copy once logged; `Indexes::sync_sent` sends each `sync.0` write to a sync-alone holder once): new store behaviour on the holder's node.

## Baseline on main
On dd5c0a3e4 (`tools/merge-branch gate spar-review-prep --all`, ostrich, offset 532945376426; log under gate-logs/ until removed). A reviewer's failure not listed here is theirs to explain.
- **Default tests**: all pass (37 binaries, 4,580 G instructions, every binary within tools/test_cost.txt). Ignored on purpose: 14 `sync rewrite:` ignores (notes/sync-rewrite-state.md, Ignored tests) and 10 tied to issues (`rg '#\[ignore = "issues/'`).
- **Sim**: 5 scenarios at 15 seeds, none failing.
- **Properties** (107 selected), failing only as listed in tools/known_failures.txt:
  - osis-engine `retention::tests_carried::purge_by_id_reads_alike_forgotten_or_not_plain_spec_commits_5`: its coverage floor at this offset (1 purge through a name over 8 seeds), and both earlier `rate:` replays still fail as listed: issues/purge-by-id-forgetting.md.
- **Full-size sync differential** (200 seeds, `OSIS_FULL=1`, four holds of 50): 60 fail, none hang. By first panic: must-hold bodies with no entry at quiet 18; unlike the reference with the public in its roster 17; a caught-up reader lacking must-hold bodies 6; settle loop past its bound 5; older reads classes 9; sync set unlike the model 4; entries waiting for a read secret 1. Seeds per class: issues/differential-full-size-classes.md. Not gate tests: no known lines.

## Gate time
Tess's cap is 10 minutes on ostrich (`gate` 260 u wall = 598 s, 3,560 u CPU = 8,188 s; notes/time-limits.md). The full selection above, at box load 35-46:
- `gate`: 784 s wall (1.31x the cap), 7,383 CPU-s (0.9x). Lock wait and `build` (warm, 0 s) left out.
- Hold 655 s wall (1.36x `gate.hold`): default tests 217 s / 1,645 CPU-s (within share); properties 421 s / 5,251 CPU-s (1.95x wall, 1.37x CPU over share); sim 14 s / 140 CPU-s; replays 3 s.
- Outside the hold, over share: `gate.gui-tests` 89 s / 169 CPU-s (9.7x wall: it compiles inside its stage), `gate.unify` 16 s / 162 CPU-s (1.76x CPU), `gate.checks` 15 s / 66 CPU-s (1.43x CPU).
- Costliest properties (CPU-s): `order::held_set_decides_plain` 806 (with its two failing seeds), `rotation_holds_large` 641, roles-model `small_family_holds_large` 420, `held_set_decides_exhaustive` 395, `deep_departure_holds_large` 380, roles-model `random_worlds_hold_large` 309, held-model `joint_one_sync_id_and_key_parts_act_as_everything_plain` 245, `evidence_over_story_worlds_large` 218: these eight are 3,414 of 5,251.
- The review's gate (`--base e8f9ae5d4^`) selects every crate, the GUI and unification as `--all` does: expect about 13 min wall at that load and a CPU total just under the cap (an end gate runs every stage against shares sized for a selection: notes/time-limits.md, Patterns). The wall at a quiet box is bounded by the properties' tail (the costliest test alone 109 s wall).
- The full-size differential is a separate cost: 4,920 CPU-s, about 8 min wall over four holds.
