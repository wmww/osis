#![allow(clippy::unwrap_used)]
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Tid, Value};

/// A thing whose mint admin is `admin`, made and committed by peer 0.
fn thing(lp: &mut LocalPeer, admin: Tid) -> Tid {
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, admin);
    m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.hold(t);
    t
}

mod tests {
    #![allow(clippy::unwrap_used)]
    use super::thing;

    // spec/wire.md §4 field 2: the split form judges as the clear form does for the same write:
    // a node writing its own thing, a thing minted with it as admin and a thing of another account it
    // writes, once in each form (`engine::write::FORCE_SPLIT`), every other node reading what it
    // reads ends with the same values and the same verdicts; reopened, the same.
    #[test]
    fn split_and_clear_forms_apply_alike_spec_wire_4() {
        let run = |split: bool| {
            let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
            lp.sync_all().unwrap();
            let (me, b) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
            let (t, g) = (thing(&mut lp, me), thing(&mut lp, me));
            let edge = ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None };
            lp.peers[0].engine.grant(&g, &b, &edge).unwrap();
            let o = {
                let mut m = Mutation::new();
                let o = lp.peers[1].engine.new_thing(&mut m, b);
                m.set(o, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(2)).unwrap();
                lp.peers[1].commit(m).unwrap();
                lp.hold(o);
                o
            };
            lp.sync_all().unwrap();
            let a = osis_base::Ak::new("x:a.0").unwrap();
            let mut m = Mutation::new();
            let x = lp.peers[1].engine.new_thing(&mut m, o);
            for (n, y) in [g, o, x].into_iter().enumerate() {
                m.set(y, &a, &Value::Int(10 + n as i64)).unwrap();
            }
            crate::engine::write::FORCE_SPLIT.with(|f| f.set(split));
            let id = lp.peers[1].commit(m).unwrap().unwrap();
            crate::engine::write::FORCE_SPLIT.with(|f| f.set(false));
            assert_eq!(lp.peers[1].engine.header(&id).unwrap().is_split(), split);
            lp.hold(x);
            lp.sync_all().unwrap();
            for i in 0..3 {
                lp.peers[i].restart(1).unwrap();
            }
            (0..3).map(|i| {
                let e = &mut lp.peers[i].engine;
                let vals: Vec<_> = [t, g, o, x].iter().map(|y| e.get(y, &a).unwrap()).collect();
                (vals, e.core.ix.commits.get(&id).map(|m| m.valid().to_vec()))
            }).collect::<Vec<_>>()
        };
        let clear = run(false);
        assert!(clear[1].0[1..].iter().all(Option::is_some) && clear[0].0[..2].iter().all(Option::is_some) && clear.iter().all(|(_, v)| v.is_some()), "{clear:?}");
        assert_eq!(run(true), clear);
    }
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_base::{Role, Tid, Value, WallMs};
    use osis_schema::core_types as ct;
    use std::collections::BTreeSet;

    // spec/permissions.md §1, §2: the role-class aspects are written only by admins, except
    // may-grant grants, which "carry the grantee's boxes for those roles". A grant's `secrets.0` part
    // that writes another holder's box is not the grantee's: it gets no may-grant exemption.
    #[test]
    fn may_grant_grant_secrets_limited_to_grantee_spec_perm_2() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let (b, c) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, me);
        let edge = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        let done = lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        let grant = *done.commits.last().unwrap();
        let h = lp.peers[0].engine.header(&grant).unwrap();
        let ai = h.aspects.iter().position(|a| a.ak.as_str() == "secrets.0").unwrap();
        // an admin's grant writes remove + put (no exemption needed): valid as the admin's
        assert!(lp.peers[0].engine.core.ix.commits.get(&grant).unwrap().valid()[ai], "an honest grant");
        // a grant of c that also writes a box keyed to b
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (bk, bx) = s.boxes.iter().find(|(k, _)| k.holder == osis_base::Weak(b)).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &edge).unwrap();
        let w = osis_keys::SecretsWrite { boxes: [(bk, bx)].into_iter().collect(), ..Default::default() };
        crate::flows::put_secrets(&mut m, t, &w, true).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let h = lp.peers[0].engine.header(&id).unwrap();
        let ai = h.aspects.iter().position(|a| a.ak.as_str() == "secrets.0").unwrap();
        assert!(lp.peers[0].engine.core.ix.overreach.contains(&(id, ai)));
    }
    // spec/wire.md §4 Pieces, spec/permissions.md §2, §3: a
    // may-grant holder's grant boxing its grantee and, beside it, a junk box keyed to the admin:
    // the junk piece is an overreach and invalid, the grantee's piece stands and the grantee
    // reads the thing. Judged as one delta, the junk voids the grantee's box with it.
    #[test]
    fn a_grantees_box_stands_beside_a_junk_box_spec_wire_4() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, a);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { may_grant: true, ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        let s = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (ak, ab) = s.boxes.iter().find(|(k, _)| k.holder == osis_base::Weak(a)).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        lp.peers[1].engine.core.junk_boxes = Some(osis_keys::SecretsWrite { boxes: [(ak, ab)].into_iter().collect(), ..Default::default() });
        lp.peers[1].engine.core.skip_writer_rules = true;
        let id = *lp.peers[1].engine.grant(&t, &c, &read).unwrap().commits.last().unwrap();
        lp.peers[1].engine.core.skip_writer_rules = false;
        lp.sync_all().unwrap();
        let h = lp.peers[2].engine.header(&id).unwrap();
        let named = lp.peers[2].engine.holders_named(&id);
        let piece = |x: osis_base::Tid| h.aspect_parts(&t, "secrets.0").find(|ai| named.get(ai).is_some_and(|hs| hs.contains(&x))).unwrap();
        let m = lp.peers[2].engine.core.ix.commits.get(&id).unwrap().clone();
        assert!(m.valid_at(piece(c)), "the grantee's piece stands");
        assert!(!m.valid_at(piece(a)), "the junk piece is an overreach");
        assert!(lp.peers[2].engine.epochs(&t).is_some_and(|e| e.read.held().next().is_some()), "the grantee holds t's read secret");
        // each piece is a piece; any two joined (two holders', a holder's beside the rest) is
        // none, and holds nothing at a receiver (`osis_commit::is_piece`)
        let e = &mut lp.peers[0].engine;
        let pieces: Vec<osis_crdt::Fragment> = h.aspect_parts(&t, "secrets.0").map(|ai| e.read(|tx| crate::apply::held_fragment(tx, &id, ai)).unwrap().unwrap()).collect();
        assert_eq!(pieces.len(), 3, "the grantee's, the junk and the rest");
        assert!(pieces.iter().all(osis_commit::is_piece));
        for (i, x) in pieces.iter().enumerate() {
            for y in &pieces[i + 1..] {
                let mut j = x.clone();
                j.join(y.clone());
                assert!(!osis_commit::is_piece(&j), "two pieces joined");
            }
        }
    }
    // spec/permissions.md §4 Copies, Key part: a grant's edge piece (its fire, sealed copy or
    // offer) carries its grantee's `secrets.0` piece and, to a grantee reading the thing, the rest
    // piece (history boxes); to a grantee of sync alone, or one removed, its piece only: the sync
    // role's history box it would open names the thing's departed holders.
    #[test]
    fn an_edge_piece_carries_the_rest_only_to_a_reader_spec_permissions_4() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, a);
        let edge = |role| ct::Edge { role, until: None, may_grant: false, retain: false, floor: None };
        let pieces = |lp: &mut LocalPeer, id: &osis_base::CommitId, h: Tid| {
            let copy = lp.peers[0].engine.edge_piece_copy(id, &t, &h).unwrap().unwrap();
            let blob = osis_commit::CommitBlob::decode(&copy).unwrap();
            let named = lp.peers[0].engine.holders_named(id);
            let mut out: Vec<BTreeSet<Tid>> = blob.parts.iter().filter(|p| blob.header.aspects[p.ai].tid == t && blob.header.aspects[p.ai].ak.as_str() == "secrets.0").map(|p| named[&p.ai].clone()).collect();
            out.sort();
            out
        };
        let gb = *lp.peers[0].engine.grant(&t, &b, &edge(Role::Read)).unwrap().commits.last().unwrap();
        let gc = *lp.peers[0].engine.grant(&t, &c, &edge(Role::Sync)).unwrap().commits.last().unwrap();
        assert_eq!(pieces(&mut lp, &gb, b), vec![BTreeSet::new(), BTreeSet::from([b])], "a reader: its piece and the rest");
        assert_eq!(pieces(&mut lp, &gc, c), vec![BTreeSet::from([c])], "sync alone: its piece only");
        let rb = *lp.peers[0].engine.demote(&t, &crate::flows::edges::Demotion { holder: b, new: None, retain: None }).unwrap().commits.last().unwrap();
        assert!(pieces(&mut lp, &rb, b).iter().all(|n| !n.is_empty()), "removed: no rest");
    }
    // spec/permissions.md §4 Copies (held-model `box_cut` `granted_after_a_removal`): o is
    // granted read and removed (the rotation's history boxes name it), then t is granted read with
    // history: t's edge piece alone (its piece and the rest) gives it the read epoch before its
    // grant, by the history box its own epoch opens; without the rest, not. Granted sync alone, t's
    // piece comes without the rest, though the grant writes one.
    #[test]
    fn a_grantee_reads_its_history_by_the_rest_spec_permissions_4() {
        let run = |role: Role, rest: bool| {
            let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
            lp.sync_all().unwrap();
            let (a, o, t) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
            let x = thing(&mut lp, a);
            let edge = |role| ct::Edge { role, until: None, may_grant: false, retain: false, floor: None };
            lp.peers[0].engine.grant(&x, &o, &edge(Role::Read)).unwrap();
            lp.peers[0].engine.demote(&x, &crate::flows::edges::Demotion { holder: o, new: None, retain: None }).unwrap();
            let g = *lp.peers[0].engine.grant(&x, &t, &edge(role)).unwrap().commits.last().unwrap();
            let named = lp.peers[0].engine.holders_named(&g);
            let secrets = osis_base::Ak::new("secrets.0").unwrap();
            let parts: Vec<usize> = lp.peers[0].engine.core.ix.commits[&g].aspect_parts(&x, &secrets).collect();
            assert!(parts.iter().any(|ai| named[ai].is_empty()), "the grant writes a rest piece");
            let mut p = lp.peers[0].engine.edge_piece(&g, &x, crate::sync_ids::Cut::EdgePiece(t)).unwrap().unwrap();
            let blob = osis_commit::CommitBlob::decode(&p.copy).unwrap();
            let carried = blob.parts.iter().any(|q| parts.contains(&q.ai) && named[&q.ai].is_empty());
            assert_eq!(carried, role >= Role::Read, "the rest beside t's piece only where t reads x");
            if !rest {
                p.copy = osis_commit::rewrite(&blob, |ai| named.get(&ai).is_some_and(BTreeSet::is_empty)).encode();
            }
            lp.peers[2].engine.take_edge_piece(&p, None).unwrap();
            let held = |e: &crate::Engine, r: Role| -> Vec<u64> { e.epochs(&x).map(|s| s.role(r).epochs().filter(|(_, i)| i.secret.is_some()).map(|(ep, _)| ep.n()).collect()).unwrap_or_default() };
            let at_a = held(&lp.peers[0].engine, Role::Read);
            assert!(at_a.len() > 1, "the removal rotated read: {at_a:?}");
            (held(&lp.peers[2].engine, Role::Read), at_a)
        };
        let (read, at_a) = run(Role::Read, true);
        assert_eq!(read, at_a, "a reader takes every read epoch from its piece and the rest");
        let (no_rest, _) = run(Role::Read, false);
        assert!(!no_rest.contains(&at_a[0]) && !no_rest.is_empty(), "control: without the rest, no epoch before the grant: {no_rest:?}");
        assert!(run(Role::Sync, true).0.is_empty(), "sync alone: no read epoch");
    }
    // spec/permissions.md §4 Copies, spec/wire.md §4 Pieces: a role commit boxing several
    // holders (a cut grant re-boxing the holders there, a removal rotating to the rest) reaches
    // the holder its fire is for with that holder's piece, and the rest only where it reads x:
    // never another holder's piece. The fire, as it is sealed and taken, not the cut alone.
    #[test]
    fn a_fire_carries_its_holders_piece_alone_spec_permissions_4() {
        let run = |c_role: Role, remove: bool| {
            let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
            lp.sync_all().unwrap();
            let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
            lp.takes_grants(2, c);
            lp.sync_all().unwrap();
            let x = thing(&mut lp, a);
            let edge = |role| ct::Edge { role, until: None, may_grant: false, retain: false, floor: None };
            lp.peers[0].engine.grant(&x, &b, &edge(Role::Read)).unwrap();
            let mut g = *lp.peers[0].engine.grant_with(&x, &c, &edge(c_role), crate::flows::edges::History::None).unwrap().commits.last().unwrap();
            if remove {
                g = *lp.peers[0].engine.demote(&x, &crate::flows::edges::Demotion { holder: c, new: None, retain: None }).unwrap().commits.last().unwrap();
            }
            let secrets = osis_base::Ak::new("secrets.0").unwrap();
            let named = lp.peers[0].engine.holders_named(&g);
            let pieces: Vec<usize> = lp.peers[0].engine.core.ix.commits[&g].aspect_parts(&x, &secrets).collect();
            assert!(pieces.iter().any(|ai| named[ai].contains(&b)), "the commit boxes b: {named:?}");
            lp.pass_fires(2).unwrap();
            let m = lp.peers[2].engine.core.ix.commits.get(&g).cloned().expect("c took its fire");
            let held: Vec<BTreeSet<Tid>> = pieces.iter().filter(|ai| m.holds(**ai)).map(|ai| named[ai].clone()).collect();
            (held, c)
        };
        let (held, c) = run(Role::Sync, false);
        assert_eq!(held, vec![BTreeSet::from([c])], "sync alone, re-boxed: its piece alone");
        let (held, c) = run(Role::Read, false);
        assert_eq!(held.iter().filter(|n| !n.is_empty()).cloned().collect::<Vec<_>>(), vec![BTreeSet::from([c])], "a reader: its piece and the rest, no other holder's: {held:?}");
        let (held, c) = run(Role::Sync, true);
        assert!(held.iter().all(|n| *n == BTreeSet::from([c])), "removed: no other holder's piece, no rest: {held:?}");
    }
    // spec/wire.md §4 Pieces (a `secrets.0` snapshot pieced alike), spec/commits.md §5 Covered:
    // a compaction of `secrets.0` holding several holders' boxes is written in pieces, each
    // holding one holder's records or none; a holder's edge piece of it carries its piece and the
    // rest, never another holder's; and there, its piece and the rest cover the grant it holds
    // as the whole snapshot does at the admin (the rest states the snapshot's tables whole).
    #[test]
    fn a_secrets_snapshot_travels_in_pieces_spec_wire_4() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, a);
        let secrets = osis_base::Ak::new("secrets.0").unwrap();
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        let gb = *lp.peers[0].engine.grant(&t, &b, &read).unwrap().commits.last().unwrap();
        lp.peers[0].engine.grant(&t, &c, &read).unwrap();
        let s = lp.peers[0].engine.snapshot(&t, &secrets).unwrap().unwrap();
        let named = lp.peers[0].engine.holders_named(&s);
        let parts: Vec<usize> = lp.peers[0].engine.core.ix.commits[&s].aspect_parts(&t, &secrets).collect();
        let pieces: Vec<BTreeSet<Tid>> = parts.iter().map(|ai| named.get(ai).cloned().unwrap_or_default()).collect();
        assert!(pieces.iter().all(|n| n.len() <= 1), "one holder a piece: {pieces:?}");
        for h in [b, c] {
            assert!(pieces.contains(&BTreeSet::from([h])), "{h:?}'s piece: {pieces:?}");
        }
        assert!(pieces.contains(&BTreeSet::new()), "the rest, always: {pieces:?}");
        for x in [gb, s] {
            let p = lp.peers[0].engine.edge_piece(&x, &t, crate::sync_ids::Cut::EdgePiece(b)).unwrap().unwrap();
            lp.peers[1].engine.take_edge_piece(&p, None).unwrap();
        }
        let m = lp.peers[1].engine.core.ix.commits[&s].clone();
        let mut held: Vec<BTreeSet<Tid>> = parts.iter().filter(|ai| m.holds(**ai)).map(|ai| named[ai].clone()).collect();
        held.sort();
        assert_eq!(held, vec![BTreeSet::new(), BTreeSet::from([b])], "b's piece and the rest");
        let at_a = lp.peers[0].engine.covered(&s, &gb, &t, &secrets).unwrap();
        assert_eq!(at_a, Some(true), "the snapshot covers the grant");
        assert_eq!(lp.peers[1].engine.covered(&s, &gb, &t, &secrets).unwrap(), at_a, "b's pieces cover as the whole does");
        // a snapshot written whole (b's and c's boxes in one piece, a hostile admin's) holds
        // nothing: its piece fails the shape check every receiver runs, its writer's own first
        lp.peers[0].engine.core.whole_secrets_snapshots = true;
        let w = lp.peers[0].engine.snapshot(&t, &secrets);
        assert!(matches!(w, Err(crate::Error::Data(osis_commit::Error::DeltaHash { .. }))), "a whole snapshot holds nothing: {w:?}");
    }
    // spec/commits.md §5 Bodies and deaths, spec/wire.md §4 Pieces: a piece held without its
    // siblings is the commit's body there, dated as any. A holder of sync alone takes its
    // grant's edge piece (its piece, no rest); its removal supersedes its box, so the piece it
    // holds is replaced at the removal, as at the admin holding every piece (failed with the
    // body judged by its first piece, the rest it lacks: never dated, its held writes dropped
    // at its lost access and not built again).
    #[test]
    fn a_piece_held_without_its_siblings_is_dated_spec_commits_5() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let secrets = osis_base::Ak::new("secrets.0").unwrap();
        let edge = ct::Edge { role: Role::Sync, until: None, may_grant: false, retain: false, floor: None };
        // a grant whose first piece is not b's (pieces lie in hash order)
        let (t, g) = (0..32)
            .find_map(|_| {
                let t = thing(&mut lp, a);
                let g = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
                let first = lp.peers[0].engine.core.ix.commits[&g].aspect_parts(&t, &secrets).next().unwrap();
                (!lp.peers[0].engine.holders_named(&g)[&first].contains(&b)).then_some((t, g))
            })
            .unwrap();
        let give = |lp: &mut LocalPeer, c: &osis_base::CommitId| {
            let p = lp.peers[0].engine.edge_piece(c, &t, crate::sync_ids::Cut::EdgePiece(b)).unwrap().unwrap();
            lp.peers[1].engine.take_edge_piece(&p, None).unwrap();
        };
        give(&mut lp, &g);
        let m = lp.peers[1].engine.core.ix.commits[&g].clone();
        let held: Vec<bool> = m.aspect_parts(&t, &secrets).map(|ai| m.holds(ai)).collect();
        assert_eq!(held.iter().filter(|h| **h).count(), 1, "its piece alone: {held:?}");
        assert!(held.len() > 1, "the grant is in pieces");
        let r = *lp.peers[0].engine.demote(&t, &crate::flows::edges::Demotion { holder: b, new: None, retain: None }).unwrap().commits.last().unwrap();
        give(&mut lp, &r);
        let at_a = lp.peers[0].engine.replaced_at(&g, &t, &secrets).unwrap();
        assert!(at_a.is_some());
        assert_eq!(lp.peers[1].engine.replaced_at(&g, &t, &secrets).unwrap(), at_a);
    }
    // spec/permissions.md §3 Who rotates, spec/wire.md §4 Pieces: a reader rotating read (a
    // hostile node) makes no rotation: its rest piece writes history boxes only, a history add's
    // shape, yet beside its keyset it is a rotation, which needs write. Were it counted, the
    // reader's epoch would supersede the one every holder reads under while their boxes to the
    // new one, in pieces needing write, count for nothing.
    #[test]
    fn a_readers_rotation_rotates_nothing_spec_permissions_3() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, a);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &read).unwrap();
        lp.peers[0].engine.grant(&t, &c, &read).unwrap();
        lp.sync_all().unwrap();
        let before = lp.peers[0].engine.epochs(&t).unwrap().read.current();
        lp.peers[1].engine.core.skip_writer_rules = true;
        let id = lp.peers[1]
            .engine
            .run(|tx| {
                let held = tx.core.epochs(&t).unwrap();
                let holders = crate::rotation::recipients(tx, &b, &t, &[])?;
                let mut m = Mutation::new();
                m.unchecked();
                let rot = crate::rotation::rotation_into(tx, &mut m, t, &[Role::Read].into_iter().collect(), &held, &holders, crate::rotation::Departs::No)?;
                let c = crate::Engine::commit_tx(tx, m)?;
                crate::rotation::record(tx, t, &rot)?;
                Ok(c)
            })
            .unwrap()
            .unwrap();
        lp.peers[1].engine.core.skip_writer_rules = false;
        let h = lp.peers[1].engine.header(&id).unwrap();
        assert!(h.aspect_parts(&t, "secrets.0").count() >= 3, "pieces: each holder's and the rest");
        lp.sync_all().unwrap();
        for fresh in [false, true] {
            for i in [0, 2] {
                if fresh {
                    lp.peers[i].restart(1).unwrap();
                }
                let e = lp.peers[i].engine.epochs(&t).unwrap();
                assert!(e.read.epochs().all(|(_, x)| !x.rotations.contains_key(&id)), "peer {i} (fresh load {fresh}): the reader's commit makes no rotation");
                assert_eq!(e.read.current(), before, "peer {i} (fresh load {fresh}): the current read epoch stays");
            }
        }
        // control: the admin's rotation, the same commit shape, counts
        let mine = lp.peers[0].engine.rotate_boxing_only(&[t], &[Role::Read], &[a, b, c]).unwrap().unwrap();
        lp.sync_all().unwrap();
        let e = lp.peers[2].engine.epochs(&t).unwrap();
        assert!(e.read.epochs().any(|(_, x)| x.rotations.contains_key(&mine)), "the admin's rotation counts");
        assert_ne!(e.read.current(), before);
    }
    // spec/permissions.md §2 (may-grant grant: its keys.0 only the records of its boxes), spec/crypto.md §4 (Stale: every box to a holder
    // actor is recorded beside it, whoever boxes): an may-grant holder granting an organization carries the
    // organization's box records in `keys.0` as puts keyed to its grantee: valid at a receiver, which
    // notes them. One also recording a box keyed to another holder gets no may-grant exemption.
    #[test]
    fn may_grant_grant_records_its_grantees_boxes_spec_perm_2() {
        let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, a);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { may_grant: true, ..read.clone() }).unwrap();
        let mut m = Mutation::new();
        let holder = lp.peers[2].engine.new_thing(&mut m, c);
        lp.peers[2].commit(m).unwrap();
        lp.hold(holder);
        lp.takes_grants(2, holder);
        lp.peers[2].engine.make_independent(&holder).unwrap();
        lp.sync_all().unwrap();
        let done = lp.peers[1].engine.grant(&t, &holder, &read).unwrap();
        let id = *done.commits.last().unwrap();
        lp.sync_all().unwrap();
        let h = lp.peers[3].engine.header(&id).unwrap();
        let ki = h.aspects.iter().position(|x| x.ak.as_str() == "keys.0" && x.tid == t).unwrap();
        assert!(lp.peers[3].engine.core.ix.commits.get(&id).unwrap().valid()[ki], "the may-grant grant's records are valid");
        let noted = lp.peers[3].engine.core.ix.sealed.iter().any(|(k, v)| k.0 == t && v.by.contains(&id) && v.keysets.contains_key(&holder));
        assert!(noted, "the receiver notes the organization's records");
        // the may-grant holder grants c and records a box keyed to the admin as well
        let s = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let ak = s.boxes.keys().find(|k| k.holder == osis_base::Weak(a)).unwrap().clone();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &read).unwrap();
        let w = osis_keys::SecretsWrite { sealed: [(ak, Default::default())].into_iter().collect(), ..Default::default() };
        crate::flows::put_secrets(&mut m, t, &w, true).unwrap();
        m.unchecked = true;
        lp.peers[1].engine.core.skip_writer_rules = true;
        let id = lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        let h = lp.peers[3].engine.header(&id).unwrap();
        let ki = h.aspects.iter().position(|x| x.ak.as_str() == "keys.0").unwrap();
        assert!(!lp.peers[3].engine.core.ix.commits.get(&id).unwrap().valid()[ki], "a record past its grantee is invalid");
    }
    // spec/permissions.md §2 (writing inside an entry it does not create is bad input; a new entry holding the whole grant): a received `roles.0` delta
    // writing inside an entry it did not create is bad input, whoever signed it.
    #[test]
    fn nested_holders_write_is_bad_input_spec_perm_2() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let t = thing(&mut lp, a);
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, b, &ct::Edge { role: Role::Write, until: Some(WallMs(1_700_000_100_000)), may_grant: false, retain: false, floor: None }).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.sync_all().unwrap();
        // the role field alone, into the grant's entry: admin, with the `until` left behind
        let mut m = Mutation::new();
        let path = vec![osis_crdt::PathSeg::Key(Value::Weak(b)), osis_crdt::PathSeg::Field(0)];
        m.op(t, &ct::ROLES, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(Value::Enum(2, None)) }).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        assert!(matches!(lp.peers[1].receive(&pk.bytes, pk.blobs), Err(crate::Error::BadInput(_))));
        assert_eq!(lp.peers[1].engine.roster(&t).get(&b).map(|e| e.role), Some(Role::Write));
    }
    // spec/permissions.md §2, spec/commits.md §4 (is joined on arrival): an may-grant holder's grant whose
    // `secrets.0` part boxes beyond its grantee is invalid whatever the arrival order; here the
    // `roles.0` part arrives first and the overreaching `secrets.0` part joins late.
    #[test]
    fn overreaching_grant_late_secrets_invalid_spec_perm_2() {
        let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.me();
        let (a, b, c) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2));
        let t = thing(&mut lp, a);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { may_grant: true, ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        // the may-grant holder grants c and also writes a box keyed to the admin
        let s = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (ak, ab) = s.boxes.iter().find(|(k, _)| k.holder == osis_base::Weak(a)).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &read).unwrap();
        let w = osis_keys::SecretsWrite { boxes: [(ak, ab)].into_iter().collect(), ..Default::default() };
        crate::flows::put_secrets(&mut m, t, &w, true).unwrap();
        m.unchecked = true;
        lp.peers[1].engine.core.skip_writer_rules = true;
        let id = lp.peers[1].commit(m).unwrap().unwrap();
        let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
        let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let si = blob.header.aspects.iter().position(|x| x.ak.as_str() == "secrets.0").unwrap();
        let first = osis_commit::rewrite(&blob, |ai| ai == si);
        lp.peers[3].receive(&first.encode(), pk.blobs.clone()).unwrap();
        assert!(lp.peers[3].engine.header(&id).is_some() && !lp.peers[3].engine.core.ix.pending.contains_key(&id), "applied without its secrets.0 part");
        lp.deliver(3, &pk).unwrap();
        let m = lp.peers[3].engine.core.ix.commits.get(&id).unwrap();
        assert!(!m.valid()[si], "the late overreaching part is invalid");
        assert!(lp.peers[3].engine.core.ix.overreach.contains(&(id, si)));
    }
    // spec/permissions.md §2: a may-grant grant's `secrets.0` delta carries only puts of its
    // grantees' boxes. One that also resets a box entry (here one the receiver has not seen yet)
    // or a history box is un-merged at every node whatever the arrival order: validity depends on
    // the delta alone.
    #[test]
    fn may_grant_grant_resets_unmerged_any_order_spec_perm_2() {
        use osis_crdt::{Op, PathOp, PathSeg};
        use osis_schema::Codec;
        let mut lp = LocalPeer::fresh(6, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        // 0 admin, 1 may-grant holder, 2 grantee, 3 and 4 receivers, 5 a holder whose box is reset
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.me();
        let (a, c, e) = (tid(&mut lp, 0), tid(&mut lp, 2), tid(&mut lp, 5));
        let b = tid(&mut lp, 1);
        let t = thing(&mut lp, a);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { may_grant: true, ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        // a grant of e the receivers have not seen yet
        let ge = *lp.peers[0].engine.grant(&t, &e, &read).unwrap().commits.last().unwrap();
        let ge = lp.peers[0].engine.package(&ge).unwrap().unwrap();
        lp.deliver(1, &ge).unwrap();
        let s = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let ek = s.boxes.keys().find(|k| k.holder == osis_base::Weak(e)).unwrap().clone();
        let hk = s.history.keys().next().unwrap().clone();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &read).unwrap();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(ek.to_value()) }).unwrap();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1)], op: Op::Remove(hk.to_value()) }).unwrap();
        m.unchecked = true;
        lp.peers[1].engine.core.skip_writer_rules = true;
        let bad = lp.peers[1].commit(m).unwrap().unwrap();
        let bad = lp.peers[1].engine.package(&bad).unwrap().unwrap();
        // receiver 3 gets the bad grant first, receiver 4 after the grant of e
        lp.deliver(3, &bad).unwrap();
        lp.deliver(3, &ge).unwrap();
        lp.deliver(4, &ge).unwrap();
        lp.deliver(4, &bad).unwrap();
        let want = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert!(want.boxes.contains_key(&ek) && want.history.contains_key(&hk));
        for r in [3, 4] {
            assert_eq!(lp.peers[r].engine.roster(&t).get(&c).map(|x| x.role), Some(Role::Read), "the edge itself is a valid may-grant grant");
            assert_eq!(lp.peers[r].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), want, "receiver {r}");
        }
    }
    // spec/permissions.md §2, §5.2: an earlier grant on the same edge, arriving late, leaves an
    // may-grant grant unapplied, its boxes with no exemption: judged again though its author's roles
    // did not move, as where they came in the other order.
    #[test]
    fn may_grant_grant_overtaken_on_its_edge_any_order_spec_perm_2() {
        let mut lp = LocalPeer::fresh(5, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        // 0 admin, 1 may-grant holder, 2 grantee, 3 and 4 receivers
        let (a, b, e) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, a);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { may_grant: true, ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        let by_admin = *lp.peers[0].engine.grant(&t, &e, &read).unwrap().commits.last().unwrap();
        let by_admin = lp.peers[0].engine.package(&by_admin).unwrap().unwrap();
        lp.advance(1000);
        let id = *lp.peers[1].engine.grant(&t, &e, &read).unwrap().commits.last().unwrap();
        let by_may_grant = lp.peers[1].engine.package(&id).unwrap().unwrap();
        lp.deliver(3, &by_may_grant).unwrap();
        assert!(lp.peers[3].engine.edge_write_applied(&t, &id), "applied while alone");
        lp.deliver(3, &by_admin).unwrap();
        lp.deliver(4, &by_admin).unwrap();
        lp.deliver(4, &by_may_grant).unwrap();
        let secrets = osis_base::Ak::new("secrets.0").unwrap();
        for r in [3, 4] {
            assert!(!lp.peers[r].engine.edge_write_applied(&t, &id), "receiver {r}");
        }
        assert_eq!(lp.peers[3].engine.body_valid(&id, &t, &secrets), lp.peers[4].engine.body_valid(&id, &t, &secrets));
        assert_eq!(lp.peers[3].engine.get_typed(&t, &ct::SECRETS).unwrap(), lp.peers[4].engine.get_typed(&t, &ct::SECRETS).unwrap());
    }
    // spec/permissions.md §2, §5.1 step 4: a late grant makes an may-grant holder an admin earlier,
    // so its write on another's edge turns from a may-grant grant (no audit) into an audited write
    // (restores what the holder gave up, demotes): the edge's value is the same, the holder's
    // write falls, as where the grant came first.
    #[test]
    fn may_grant_grant_turned_audited_any_order_spec_perm_5_1() {
        let mut lp = LocalPeer::fresh(5, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        // 0 admin, 1 may-grant holder, 2 holder, 3 and 4 readers receiving
        let (a, b, h) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let ak = osis_base::Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ak, &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { may_grant: true, ..read.clone() }).unwrap();
        lp.peers[0].engine.grant(&t, &h, &ct::Edge { role: Role::Write, ..read.clone() }).unwrap();
        for r in [3, 4] {
            let who = lp.peers[r].engine.me();
            lp.peers[0].engine.grant(&t, &who, &read).unwrap();
        }
        lp.hold(t);
        lp.sync_all().unwrap();
        // the holder writes (no one hears yet), then gives its edge up
        lp.advance(1000);
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(2)).unwrap();
        let write = lp.peers[2].commit(m).unwrap().unwrap();
        let write = lp.peers[2].engine.package(&write).unwrap().unwrap();
        lp.advance(1000);
        let left = crate::flows::Demotion { holder: h, new: None, retain: None };
        let left = *lp.peers[2].engine.demote(&t, &left).unwrap().commits.last().unwrap();
        let left = lp.peers[2].engine.package(&left).unwrap().unwrap();
        lp.deliver(1, &left).unwrap();
        lp.advance(1000);
        let to_admin = *lp.peers[0].engine.grant(&t, &b, &ct::Edge { role: Role::Admin, ..read.clone() }).unwrap().commits.last().unwrap();
        let to_admin = lp.peers[0].engine.package(&to_admin).unwrap().unwrap();
        lp.advance(1000);
        // a may-grant grant at its author, which has heard neither the write nor the rise
        // (by hand: an honest writer waits for the rotation; the walk does not care)
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, h, &read).unwrap();
        m.unchecked = true;
        lp.peers[1].engine.core.skip_writer_rules = true;
        let again = lp.peers[1].commit(m).unwrap().unwrap();
        lp.peers[1].engine.core.skip_writer_rules = false;
        let again = lp.peers[1].engine.package(&again).unwrap().unwrap();
        let id = write.id;
        for pk in [&write, &left, &again] {
            lp.deliver(3, pk).unwrap();
        }
        assert_eq!(lp.peers[3].engine.body_valid(&id, &t, &ak), Some(true), "no audit yet");
        lp.deliver(3, &to_admin).unwrap();
        for pk in [&to_admin, &write, &left, &again] {
            lp.deliver(4, pk).unwrap();
        }
        for r in [3, 4] {
            assert_eq!(lp.peers[r].engine.body_valid(&id, &t, &ak), Some(false), "receiver {r}");
        }
    }
    // spec/permissions.md §2: a may-grant grant's `secrets.0` entries are new, created by its own
    // delta. A record claiming the grantee's key at another holder's entry dot would merge into
    // that entry (the stored key wins), overwriting its box: not a put, no may-grant exemption.
    #[test]
    fn may_grant_grant_foreign_entry_dot_rejected_spec_perm_2() {
        use osis_crdt::{DeltaBuilder, Dot, Encoding, SlotRef, Op, PathOp, PathSeg, Source, Writer};
        use osis_schema::Codec;
        fn box_entries(f: &osis_crdt::Fragment) -> Vec<(Dot, Option<Value>)> {
            let Some(SlotRef::Frag(osis_crdt::Fragment::Struct(st))) = f.slot(Encoding::Struct) else { return Vec::new() };
            let Some(SlotRef::Frag(osis_crdt::Fragment::Map(m))) = st.field(0).and_then(|x| x.slot(Encoding::Map)) else { return Vec::new() };
            m.entries().map(|(d, _, k, _)| (d.clone(), k.cloned())).collect()
        }
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b, g) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, a);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: true, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &read).unwrap();
        let ak = osis_base::Ak::new("secrets.0").unwrap();
        let st = lp.peers[0].engine.state(&t, &ak).unwrap().unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        // the admin's own box entry
        let (a_dot, a_key) = box_entries(&st).into_iter().find_map(|(d, k)| Some((d, ct::BoxKey::from_value(&k?).ok().filter(|k| k.holder == osis_base::Weak(a))?))).unwrap();
        let bx = s.boxes.get(&a_key).unwrap().clone();
        let g_key = ct::BoxKey { holder: osis_base::Weak(g), role: Role::Read, epoch: a_key.epoch.clone() };
        let schema = osis_schema::core_schema();
        let view = schema.view("secrets.0").unwrap();
        let ts = osis_base::Ts::make(WallMs(1_700_000_000_100), 0).unwrap();
        let mut builder = DeltaBuilder::new(&st, Writer::new(ts, Source::session(osis_crdt::Session { node: b, nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), 1));
        builder.apply(&PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(g_key.to_value())], op: Op::Put(bx.to_value()) }, &view).unwrap();
        let (d, range) = builder.finish().unwrap();
        let own = crate::engine::Owned::Range { src: Source::session(osis_crdt::Session { node: b, nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), lo: range.lo, hi: range.hi };
        let granted = std::collections::BTreeMap::from([((t, g), Role::Read)]);
        assert!(super::super::validity::grantee_boxes_only(&t, "secrets.0", &d, &granted, &own), "an honest put");
        // the same put written at the admin's entry dot
        let mut builder = DeltaBuilder::new(&st, Writer::new(ts, a_dot.src.clone(), a_dot.ctr));
        builder.apply(&PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(g_key.to_value())], op: Op::Put(bx.to_value()) }, &view).unwrap();
        let (forged, _) = builder.finish().unwrap();
        assert_eq!(box_entries(&forged).remove(0).0, a_dot);
        assert!(!super::super::validity::grantee_boxes_only(&t, "secrets.0", &forged, &granted, &own), "a write into the admin's entry");
    }
    // spec/permissions.md §1: a record chain reaches its top within `MAX_CHAIN_DEPTH`
    // links; a delta written on a thing deeper is invalid and the rest of its commit applies, at
    // every node alike. The writer refuses such a commit.
    #[test]
    fn record_chain_deeper_than_cap_invalid_spec_permissions_1() {
        use osis_base::format::MAX_CHAIN_DEPTH;
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let x = osis_base::Ak::new("x:a.0").unwrap();
        let mut up = lp.peers[0].engine.me();
        let mut shallow = up;
        for i in 0..MAX_CHAIN_DEPTH {
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, up);
            m.set(t, &x, &Value::Int(1)).unwrap();
            lp.peers[0].commit(m).unwrap();
            lp.hold(t);
            if i == 0 {
                shallow = t;
            }
            up = t;
        }
        let at_cap = up;
        // the other peers read the chain: what they hold of a thing outside their node closure is
        // its certificates alone (spec/commits.md §5 What a held thing needs)
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        for r in [1, 2] {
            let who = lp.peers[r].engine.me();
            lp.peers[0].engine.grant(&shallow, &who, &read).unwrap();
        }
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[1].engine.get(&at_cap, &x).unwrap(), Some(Value::Int(1)), "at the cap: applies");
        // one commit writing a shallow thing and a thing one link too deep
        let mut m = Mutation::new();
        let d = lp.peers[0].engine.new_thing(&mut m, up);
        m.set(d, &x, &Value::Int(9)).unwrap();
        m.set(shallow, &x, &Value::Int(2)).unwrap();
        assert!(lp.peers[0].commit(m.clone()).is_err(), "the writer refuses it");
        lp.peers[0].engine.core.skip_writer_rules = true;
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        lp.hold(d);
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        for r in [0, 1, 2] {
            if r > 0 {
                lp.deliver(r, &pk).unwrap();
            }
            assert_eq!(lp.peers[r].engine.get(&shallow, &x).unwrap(), Some(Value::Int(2)), "peer {r}");
            assert_eq!(lp.peers[r].engine.get(&d, &x).unwrap(), None, "peer {r}");
        }
    }
    // spec/permissions.md §1: the cap counts mint-admin links (the record chain), whether the
    // things were made with a write or by their record alone: a chain at `MAX_CHAIN_DEPTH`
    // links applies; one link more is invalid, at the writer and at receivers.
    #[test]
    fn record_chain_through_mint_admins_capped_spec_permissions_1() {
        use osis_base::format::MAX_CHAIN_DEPTH;
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let x = osis_base::Ak::new("x:a.0").unwrap();
        let mut up = lp.peers[0].engine.me();
        let mut top = up;
        for i in 0..MAX_CHAIN_DEPTH {
            let t = if i % 4 == 0 {
                lp.peers[0].engine.create_with_admin(&up).unwrap().0
            } else {
                // held in `top`'s sync unit, so `top`'s sync ID carries it (a node root's unit is
                // local, spec/sync-set.md §1)
                let mut m = Mutation::new();
                let t = lp.peers[0].engine.new_thing(&mut m, up);
                m.op(top, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
                lp.peers[0].commit(m).unwrap();
                t
            };
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Int(1)).unwrap();
            lp.peers[0].commit(m).unwrap();
            if i == 0 {
                top = t;
            }
            up = t;
        }
        // peer 1 reads the chain (`record_chain_deeper_than_cap_invalid_spec_permissions_1`)
        let who = lp.peers[1].engine.me();
        lp.peers[0].engine.grant(&top, &who, &ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.hold_at(1, top);
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[1].engine.get(&up, &x).unwrap(), Some(Value::Int(1)), "at the cap: applies");
        let mut m = Mutation::new();
        let d = m.create(osis_base::CreationRecord::with_admin(up, [7; 32]));
        m.set(d, &x, &Value::Int(9)).unwrap();
        assert!(lp.peers[0].commit(m.clone()).is_err(), "the writer refuses it");
        lp.peers[0].engine.core.skip_writer_rules = true;
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        for r in [0, 1] {
            assert_eq!(lp.peers[r].engine.get(&d, &x).unwrap(), None, "peer {r}");
        }
    }
    // spec/permissions.md §1: an edge write on a thing too deep is invalid like any of its
    // deltas: it never reaches perm (else a deep actor's holders would gain its roles on a
    // shallow thing it is a holder of), at the writer and at receivers.
    #[test]
    fn edge_on_deep_thing_not_held_spec_permissions_1() {
        use osis_base::format::MAX_CHAIN_DEPTH;
        use osis_base::Tid;
        use osis_crdt::{Op, PathOp, PathSeg};
        use osis_schema::Codec;
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let x = lp.peers[1].engine.me();
        let mut up = me;
        for i in 0..MAX_CHAIN_DEPTH {
            let mut m = Mutation::new();
            up = lp.peers[0].engine.new_thing(&mut m, up);
            lp.peers[0].commit(m).unwrap();
            // the chain's top keeps delete keys of its own: the things below list them
            if i == 0 {
                lp.peers[0].engine.make_independent(&up).unwrap();
            }
        }
        let mut m = Mutation::new();
        let shallow = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        lp.hold(shallow);
        let edge_in = |m: &mut Mutation, t: Tid, holder: Tid| {
            m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Weak(holder))], op: Op::Set(ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }.to_value()) }).unwrap();
        };
        let edge = |t: Tid, holder: Tid| {
            let mut m = Mutation::new();
            edge_in(&mut m, t, holder);
            m
        };
        lp.peers[0].engine.core.skip_writer_rules = true;
        let mut m = Mutation::new();
        let deep = lp.peers[0].engine.new_thing(&mut m, up);
        // made and held, then its raw edge (a role commit)
        lp.peers[0].commit(m).unwrap();
        lp.hold(deep);
        let mut m = Mutation::new();
        edge_in(&mut m, deep, x);
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].commit(edge(shallow, deep)).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = false;
        lp.sync_all().unwrap();
        assert!(lp.peers[1].engine.header(&c).is_some(), "applied at the receiver");
        for r in [0, 1] {
            let held = &lp.peers[r].engine.core.ix.held;
            assert!(held.edge_commits(&deep).is_empty(), "peer {r}");
            assert!(!held.edge_commits(&shallow).is_empty(), "peer {r}: the shallow edge counts");
        }
    }
    // spec/permissions.md §2: the may-grant exemption is for an applied may-grant grant's boxes. A
    // reader pairing its own removal (which always applies) with a put that fails gets no
    // exemption: its boxes for the failed grantee and its history boxes are judged as its own
    // `secrets.0` write (admin), invalid. A redemption-shaped grant by an may-grant holder stays valid.
    #[test]
    fn self_removal_beside_failing_grant_no_exemption_spec_perm_2() {
        use osis_base::Tid;
        use osis_crdt::{Op, PathOp};
        let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.me();
        let (a, r, z, g) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3));
        let t = thing(&mut lp, a);
        let read = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &r, &read).unwrap();
        lp.sync_all().unwrap();
        let before = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (rk, rb) = before.boxes.iter().find(|(k, _)| k.holder == osis_base::Weak(r)).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let zk = ct::BoxKey { holder: osis_base::Weak(z), role: Role::Admin, epoch: rk.epoch.clone() };
        let hk = ct::HistoryKey { role: Role::Admin, epoch: rk.epoch.clone() };
        let commit = |lp: &mut LocalPeer, who: Tid, edge: ct::Edge, i: usize| {
            let mut m = Mutation::new();
            m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Weak(lp.peers[i].engine.me())) }).unwrap();
            crate::flows::put_edge(&mut m, t, who, &edge).unwrap();
            let k = ct::BoxKey { holder: osis_base::Weak(who), role: edge.role, ..zk.clone() };
            let h = ct::HistoryKey { role: edge.role, ..hk.clone() };
            let w = osis_keys::SecretsWrite { boxes: [(k, rb.clone())].into_iter().collect(), history: [(h, vec![0; 48])].into_iter().collect(), ..Default::default() };
            crate::flows::put_secrets(&mut m, t, &w, true).unwrap();
            m.unchecked = true;
            lp.peers[i].engine.core.skip_writer_rules = true;
            let id = lp.peers[i].commit(m).unwrap().unwrap();
            lp.peers[i].engine.core.skip_writer_rules = false;
            let pk = lp.peers[i].engine.package(&id).unwrap().unwrap();
            lp.deliver(0, &pk).unwrap();
            let h = lp.peers[0].engine.header(&id).unwrap();
            let si = h.aspects.iter().position(|x| x.ak.as_str() == "secrets.0").unwrap();
            lp.peers[0].engine.core.ix.commits.get(&id).unwrap().valid()[si]
        };
        // the reader's self-removal plus a put of z at admin (no authority: fails)
        assert!(!commit(&mut lp, z, ct::Edge { role: Role::Admin, ..read.clone() }, 1), "no exemption beside a failing put");
        assert_eq!(lp.peers[0].engine.roster(&t).get(&z), None);
        assert!(!lp.peers[0].engine.roster(&t).contains_key(&r), "the self-removal applies");
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert!(!s.boxes.contains_key(&zk) && s.history.get(&hk) != Some(&vec![0; 48]));
        // honest shape: an may-grant holder's grant of g plus its own removal (a redemption)
        lp.peers[0].engine.grant(&t, &z, &ct::Edge { may_grant: true, ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        assert!(commit(&mut lp, g, ct::Edge { role: Role::Read, ..read.clone() }, 2), "an applied may-grant grant's boxes");
        assert_eq!(lp.peers[0].engine.roster(&t).get(&g).map(|e| e.role), Some(Role::Read));
    }
}

mod keys_tests {
    #![allow(clippy::unwrap_used)]
    use super::thing;
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_base::{Role, Value, WallMs};
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::core_types as ct;
    use osis_schema::Codec;

    // spec/crypto.md §3: the deposit seed is an admin's to write. A writer's `keys.0` write of it
    // is invalid: otherwise a writer (kept valid by its demoter's frontier after removal) chose
    // the key every deposit to the thing is signed with.
    #[test]
    fn writer_cannot_write_admin_keys_fields_spec_crypto_3() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let w = lp.peers[1].engine.me();
        let t = thing(&mut lp, me);
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Write));
        let before = lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        let mut m = Mutation::new();
        m.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(5)], op: Op::Set(Some([9u8; 32]).to_value()) }).unwrap();
        assert!(lp.peers[1].commit(m.clone()).is_err(), "refused writer-side");
        lp.peers[1].engine.core.skip_writer_rules = true;
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.peers[1].engine.core.skip_writer_rules = false;
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap(), before);
        // spec/permissions.md §3: a writer rotates read and write only; an admin history box is
        // an admin's write
        let e = lp.peers[0].engine.epochs(&t).unwrap().admin.newest().unwrap();
        let hk = ct::HistoryKey { role: Role::Admin, epoch: osis_keys::aspects::to_schema(&e) };
        let mut m = Mutation::new();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(hk.to_value())], op: Op::Set(Value::Bytes(vec![0; 48])) }).unwrap();
        assert!(lp.peers[1].commit(m.clone()).is_err(), "refused writer-side");
        lp.peers[1].engine.core.skip_writer_rules = true;
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.peers[1].engine.core.skip_writer_rules = false;
        lp.sync_all().unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert_ne!(s.history.get(&hk), Some(&vec![0; 48]));
    }

    /// Peer 1 commits `m` past the writer-side rules (they refuse it first).
    fn force(lp: &mut LocalPeer, i: usize, mut m: Mutation) {
        assert!(lp.peers[i].commit(m.clone()).is_err(), "refused writer-side");
        m.unchecked();
        lp.peers[i].engine.core.skip_writer_rules = true;
        lp.peers[i].commit(m).unwrap().unwrap();
        lp.peers[i].engine.core.skip_writer_rules = false;
    }

    // spec/permissions.md §3 (who rotates; a write or reset of the whole value),
    // spec/crypto.md §3: a write or reset of the whole `keys.0` or `secrets.0` value replaces the
    // admin fields and every box: an admin's write, invalid from a writer
    #[test]
    fn writer_cannot_replace_keys_or_secrets_spec_perm_3() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let w = lp.peers[1].engine.me();
        let t = thing(&mut lp, me);
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        let keys = lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        let secrets = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        for ak in ["keys.0", "secrets.0"] {
            let mut m = Mutation::new();
            m.set(t, &osis_base::Ak::new(ak).unwrap(), &Value::Int(1)).unwrap();
            force(&mut lp, 1, m);
        }
        // a root reset with writer fields only
        let mut k = keys.clone();
        k.admin = None;
        let mut m = Mutation::new();
        m.replace(t, &ct::KEYS, &k).unwrap();
        force(&mut lp, 1, m);
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap(), keys);
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), secrets);
    }

    // spec/permissions.md §5.2: a compaction snapshot of `keys.0` or `secrets.0` needs admin (the
    // strictest role a write it carries could need). Else a writer's `keys.0` snapshot carrying a
    // forged admin keyset under a dot nobody holds joined at every receiver, and later admin
    // secrets were sealed to the writer.
    #[test]
    fn writer_snapshot_of_keys_invalid_spec_perm_5_2() {
        use osis_crdt::{DeltaBuilder, Source, Writer};
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let w = lp.peers[1].engine.me();
        let t = thing(&mut lp, me);
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        let keys_ak = osis_base::Ak::new("keys.0").unwrap();
        let before = lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        assert!(matches!(lp.peers[1].engine.snapshot(&t, &keys_ak), Err(crate::Error::Permission { .. })), "refused writer-side");
        // the writer's state with a forged admin keyset (its write keyset) under a dot nobody holds
        let forged = before.write.clone().unwrap();
        assert_ne!(Some(&forged), before.admin.as_ref());
        let st = lp.peers[1].engine.state(&t, &keys_ak).unwrap().unwrap();
        let ts = lp.peers[1].engine.core.hlc.next();
        let view = osis_schema::core_schema().view("keys.0").unwrap();
        let mut builder = DeltaBuilder::new(&st, Writer::new(ts, Source::commit(osis_base::CommitId([7; 32])), 1));
        builder.apply(&PathOp { path: vec![PathSeg::Field(2)], op: Op::Set(Some(forged.clone()).to_value()) }, &view).unwrap();
        let (d, _) = builder.finish().unwrap();
        let mut st = st.clone();
        st.join(d);
        // a state no held body gives (`apply::check_rebuilt` would refuse it)
        let snap = lp.peers[1]
            .engine
            .run(|tx| {
                tx.core.unchecked_tx = true;
                tx.core.skip_writer_rules = true;
                tx.core.states.insert((t, keys_ak.clone()), Some(st));
                let snap = crate::retention::write_snapshot(tx, &t, &keys_ak, false);
                tx.core.skip_writer_rules = false;
                snap
            })
            .unwrap()
            .unwrap();
        let pk = lp.peers[1].engine.package(&snap).unwrap().unwrap();
        lp.deliver(0, &pk).unwrap();
        assert!(!lp.peers[0].engine.core.ix.commits.get(&snap).unwrap().valid()[0], "a writer's keys.0 snapshot is invalid");
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap(), before);
    }

    // spec/permissions.md §3, spec/crdt.md §5.6: writers W1 and W2 both remove read box X; the
    // admin compacts after W1, drops X's creation and W1's body, then gets W2. A removal carries
    // X's key, so W2 needs the read role wherever it is judged: valid at open, after a rebuild
    // and at every node.
    #[test]
    fn secrets_removal_dropped_creation_open_equals_rebuild() {
        let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.me();
        let (me, w1, w2, r) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3));
        let t = thing(&mut lp, me);
        let we = ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &w1, &we).unwrap();
        lp.peers[0].engine.grant(&t, &w2, &we).unwrap();
        let g = *lp.peers[0].engine.grant(&t, &r, &ct::Edge { role: Role::Read, ..we.clone() }).unwrap().commits.last().unwrap();
        lp.sync_all().unwrap();
        let rk = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap().boxes.keys().find(|k| k.holder == osis_base::Weak(r)).unwrap().clone();
        let rm = |lp: &mut LocalPeer, i: usize| {
            let mut m = Mutation::new();
            m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(rk.to_value()) }).unwrap();
            let id = lp.peers[i].commit(m).unwrap().unwrap();
            (id, lp.peers[i].engine.package(&id).unwrap().unwrap())
        };
        let (c1, p1) = rm(&mut lp, 1);
        let (c2, p2) = rm(&mut lp, 2);
        lp.deliver(0, &p1).unwrap();
        let secrets = osis_base::Ak::new("secrets.0").unwrap();
        lp.peers[0].engine.snapshot(&t, &secrets).unwrap().unwrap();
        lp.peers[0].engine.drop_body(&g, &t, &secrets).unwrap();
        lp.peers[0].engine.drop_body(&c1, &t, &secrets).unwrap();
        lp.deliver(0, &p2).unwrap();
        let v = |lp: &LocalPeer| lp.peers[0].engine.core.ix.commits.get(&c2).unwrap().valid()[0];
        assert!(v(&lp), "a writer's removal of a read box");
        let d0 = lp.peers[0].engine.index_digest();
        lp.peers[0].engine.rebuild_index().unwrap();
        assert!(v(&lp), "rebuilt alike");
        // the whole index alike: what dropped bodies noted went with them, or is in their records
        assert_eq!(d0.first_diff(&lp.peers[0].engine.index_digest()), None);
        lp.sync_all().unwrap();
        let want = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert!(!want.boxes.contains_key(&rk));
        for i in 0..4 {
            assert!(lp.peers[i].engine.core.ix.commits.get(&c2).unwrap().valid()[0], "peer {i}");
            assert_eq!(lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), want, "peer {i}");
        }
    }

    // spec/crypto.md §4 (Carried: a keyset's rotation commit; held keyset), spec/commits.md §5:
    // admin P rotates read (removing R); the mint admin grants X at that epoch, compacts and drops P's
    // rotation bodies. The epoch's introducer stays P's rotation (not the later grant), at open and
    // after a rebuild; the keyset stays held.
    #[test]
    fn dropped_rotation_keeps_its_epoch_intro_spec_crypto_4() {
        let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.me();
        let (me, p, r, x) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3));
        let t = thing(&mut lp, me);
        let e = |role| ct::Edge { role, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &p, &e(Role::Admin)).unwrap();
        lp.peers[0].engine.grant(&t, &r, &e(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let rot = lp.peers[1].engine.demote(&t, &crate::flows::Demotion { holder: r, new: None, retain: None }).unwrap().commits;
        lp.sync_all().unwrap();
        let ep = lp.peers[0].engine.core.epochs(&t).unwrap().role(Role::Read).newest().unwrap();
        let intro = |lp: &LocalPeer| lp.peers[0].engine.core.ix.epoch_intro.get(&(t, Role::Read, ep)).map(|v| v.1);
        let p = rot.iter().copied().find(|c| lp.peers[0].engine.core.ix.commits.contains_key(c));
        assert!(p.is_some());
        assert_eq!(intro(&lp), p);
        lp.peers[0].engine.grant(&t, &x, &e(Role::Read)).unwrap();
        for k in ["secrets.0", "keys.0"] {
            let k = osis_base::Ak::new(k).unwrap();
            lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
            for c in &rot {
                if lp.peers[0].engine.body_not_dropped(c, &t, &k) {
                    lp.peers[0].engine.drop_body(c, &t, &k).unwrap();
                }
            }
        }
        assert!(rot.iter().any(|c| !lp.peers[0].engine.body_not_dropped(c, &t, &osis_base::Ak::new("secrets.0").unwrap())), "rotation body dropped");
        assert_eq!(intro(&lp), p, "the rotation, not the later grant");
        let d0 = lp.peers[0].engine.index_digest();
        lp.peers[0].engine.rebuild_index().unwrap();
        assert_eq!(intro(&lp), p, "rebuilt");
        assert_eq!(d0.first_diff(&lp.peers[0].engine.index_digest()), None);
        assert!(lp.peers[0].engine.core.ix.keysets.contains_key(&(t, Role::Read, ep)), "held keyset kept");
    }

    // spec/permissions.md §3, spec/crypto.md §4: a writer rotates read and write only. A removal
    // carries its entry's key and acts only on the entry of that key (spec/crdt.md §5.6), so it
    // needs the role its key names: a writer's removal of admin boxes and admin history boxes is
    // invalid; its removal of a read box is valid, also where it arrives before the box, which
    // it then removes on arrival.
    #[test]
    fn writer_cannot_remove_admin_boxes_spec_perm_3() {
        let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.me();
        let (me, w, r) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 3));
        let t = thing(&mut lp, me);
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        let before = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let mut m = Mutation::new();
        let admin: Vec<_> = before.boxes.keys().filter(|k| k.role == Role::Admin).cloned().collect();
        let hist: Vec<_> = before.history.keys().filter(|k| k.role == Role::Admin).cloned().collect();
        assert!(!admin.is_empty() && !hist.is_empty());
        for k in &admin {
            m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(k.to_value()) }).unwrap();
        }
        for k in &hist {
            m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1)], op: Op::Remove(k.to_value()) }).unwrap();
        }
        force(&mut lp, 1, m);
        lp.sync_all().unwrap();
        for i in [0, 2] {
            assert_eq!(lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), before, "peer {i}");
        }
        // a read box: the writer may remove it, judged alike before and after its grant arrives
        let grant = *lp.peers[0].engine.grant(&t, &r, &ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).unwrap().commits.last().unwrap();
        let grant = lp.peers[0].engine.package(&grant).unwrap().unwrap();
        lp.deliver(1, &grant).unwrap();
        let rk = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap().boxes.keys().find(|k| k.holder == osis_base::Weak(r)).unwrap().clone();
        let mut m = Mutation::new();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(rk.to_value()) }).unwrap();
        let id = lp.peers[1].commit(m).unwrap().unwrap();
        let rm = lp.peers[1].engine.package(&id).unwrap().unwrap();
        lp.deliver(2, &rm).unwrap();
        assert!(lp.peers[2].engine.core.ix.commits.get(&id).unwrap().valid()[0], "a read box's removal, before the box");
        lp.deliver(2, &grant).unwrap();
        assert!(lp.peers[2].engine.core.ix.commits.get(&id).unwrap().valid()[0], "and after it");
        lp.deliver(0, &rm).unwrap();
        for i in [0, 1, 2] {
            assert!(!lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap().boxes.contains_key(&rk), "peer {i}");
        }
    }

    // spec/permissions.md §3, spec/crdt.md §5.6: a `secrets.0` removal's role is its record's
    // key's, whatever entry holds its dot (an equivocated or forged key acts only on the entry
    // of that key); a key-erased removal resets every record of its dot: admin
    #[test]
    fn secrets_removal_role_from_its_key_spec_perm_3() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let t = thing(&mut lp, me);
        let wt = lp.peers[1].engine.me();
        lp.peers[0].engine.grant(&t, &wt, &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let admin = s.boxes.keys().find(|k| k.role == Role::Admin).unwrap().clone();
        let read = ct::BoxKey { role: Role::Read, ..admin.clone() };
        let src = osis_crdt::Source::session(osis_crdt::Session { node: lp.peers[1].engine.me(), nonce: [0; osis_crdt::SESSION_NONCE_LEN] });
        let w = osis_crdt::Writer::new(osis_base::Ts::make(WallMs(1_700_000_000_000), 0).unwrap(), src.clone(), 1).keyed_removals(true);
        let dot = osis_crdt::Dot::new(osis_crdt::Source::session(osis_crdt::Session { node: me, nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), 3);
        let rm = |k: Option<&ct::BoxKey>| {
            let f = match k {
                Some(k) => osis_crdt::reset_entries(&w, &[(dot.clone(), k.to_value())]),
                None => osis_crdt::reset_entries(&w.clone().keyed_removals(false), &[(dot.clone(), Value::Int(0))]),
            };
            osis_crdt::Fragment::wrap(&[(osis_crdt::Step::Field(0), None, None)], f)
        };
        assert_eq!(super::super::validity::secrets_role(&rm(Some(&read))), Role::Write, "a read box's removal: at least write");
        assert_eq!(super::super::validity::secrets_role(&rm(Some(&admin))), Role::Admin);
        assert_eq!(super::super::validity::secrets_role(&rm(None)), Role::Admin, "key-erased");
        // the decoded-secrets fast path never reads a reset key as gone: it may have another
        // live entry on a page the join did not load (a box read as gone that the state held)
        let state = rm(Some(&read));
        assert!(!super::super::keys::secrets_patch(&mut ct::Secrets::default(), &rm(Some(&read)), &state), "a removal reading as gone is decoded, not patched");
    }

    // spec/permissions.md §2: a may-grant grant carries the grantee's boxes only; a write of the
    // whole `secrets.0` value is no grantee's box
    #[test]
    fn may_grant_grant_cannot_replace_secrets_spec_perm_2() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let (b, c) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let t = thing(&mut lp, me);
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { role: Role::Read, until: None, may_grant: true, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        let secrets = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        m.set(t, &osis_base::Ak::new("secrets.0").unwrap(), &Value::Int(1)).unwrap();
        force(&mut lp, 1, m);
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), secrets);
    }
}
