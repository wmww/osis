# An own cover can drop an absorbed commit under a label it was not placed under
> Summary: after a restart, an own commit X on an ephemeral thing T placed (ephemerally) in groups G1 and G2 can be covered once T's G1 placement is back but before its G2 placement is; the cover goes under L1 only, `eph_covers_held_with` counts it "outside" L2, and X's L2 entry is deleted: L2-only readers lose X's writes.
> Tags: node-sync, ephemeral

`coverable` (core/engine/src/ephemeral/remote.rs) admits a commit once each of its things is in some labeled closure here (sim `ephemeral_seed_21054` fixed the case of none). The node's view of which labels hold a thing lags after a restart: ephemeral placements are fetched back in server order, so it can know one of T's groups and not yet the other. The delete under L2 then goes through the `outside` shortcut (the cover has own entries, none under L2), and the cover is never placed under L2 later (`eph_place` runs once per built commit).

Not reproduced; reasoned from the code in review of eph-21054. Fix directions: judge `outside` against the labels X's entries are under and the parts they carry (not the local closure now), with a bound for things that really left a label (else X stays at the server for good); or no own covers of an earlier session's commits until every label was reconciled once since start.
