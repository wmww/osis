mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_base::{Role, Value, WallMs};
    use osis_schema::core_types as ct;

    // spec/permissions.md §1, §2: the role-class aspects are written only by admins, except
    // invite grants, which "carry the grantee's boxes for those roles". A grant's `secrets.0` part
    // that writes another holder's box is not the grantee's: it gets no invite exemption.
    #[test]
    fn invite_grant_secrets_limited_to_grantee_spec_perm_2() {
        let mut lp = LocalPeer::new(3, 901, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        let done = lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        let grant = *done.commits.last().unwrap();
        let h = lp.peers[0].engine.header(&grant).unwrap();
        let ai = h.aspects.iter().position(|a| a.ak.as_str() == "secrets.0").unwrap();
        // an admin's grant writes remove + put (no exemption needed): valid as the admin's
        assert!(lp.peers[0].engine.core.ix.commits.get(&grant).unwrap().valid[ai], "an honest grant");
        // a grant of c that also writes a box keyed to b
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (bk, bx) = s.boxes.iter().find(|(k, _)| k.holder == b).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &edge).unwrap();
        let w = osis_keys::SecretsWrite { boxes: [(bk, bx)].into_iter().collect(), ..Default::default() };
        crate::flows::put_secrets(&mut m, t, &w, true).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let h = lp.peers[0].engine.header(&id).unwrap();
        let ai = h.aspects.iter().position(|a| a.ak.as_str() == "secrets.0").unwrap();
        assert!(lp.peers[0].engine.core.ix.grant_overreach.contains(&(id, ai)));
    }
    // spec/permissions.md §2 (an edge change is remove + put): a received `roles.0` delta
    // writing inside an entry it did not create is bad input, whoever signed it.
    #[test]
    fn nested_holders_write_is_bad_input_spec_perm_2() {
        let mut lp = LocalPeer::new(2, 907, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, b, &ct::Edge { role: Role::Write, until: Some(WallMs(1_700_000_100_000)), invite: None, tied: None }).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.sync_all().unwrap();
        // the role field alone, into the grant's entry: admin, with the `until` left behind
        let mut m = Mutation::new();
        let path = vec![osis_crdt::PathSeg::Key(Value::Tid(b)), osis_crdt::PathSeg::Field(0)];
        m.op(t, &ct::ROLES, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(Value::Enum(2, None)) }).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        assert!(matches!(lp.peers[1].engine.ingest(&pk.bytes, pk.blobs), Err(crate::Error::BadInput(_))));
        assert_eq!(lp.peers[1].engine.roster(&t).get(&b).map(|e| e.role), Some(Role::Write));
    }
    // spec/permissions.md §2, spec/commits.md §4 (late deltas): an invite holder's grant whose
    // `secrets.0` part boxes beyond its grantee is invalid whatever the arrival order; here the
    // `roles.0` part arrives first and the overreaching `secrets.0` part joins late.
    #[test]
    fn overreaching_grant_late_secrets_invalid_spec_perm_2() {
        let mut lp = LocalPeer::new(4, 905, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (a, b, c) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { invite: Some(Role::Read), ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        // the invite holder grants c and also writes a box keyed to the admin
        let s = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (ak, ab) = s.boxes.iter().find(|(k, _)| k.holder == a).map(|(k, v)| (k.clone(), v.clone())).unwrap();
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
        lp.peers[3].engine.ingest(&first.encode(), pk.blobs.clone()).unwrap();
        assert!(lp.peers[3].engine.header(&id).is_some() && !lp.peers[3].engine.core.ix.pending.contains_key(&id), "applied without its secrets.0 part");
        lp.deliver(3, &pk).unwrap();
        let m = lp.peers[3].engine.core.ix.commits.get(&id).unwrap();
        assert!(!m.valid[si], "the late overreaching part is invalid");
        assert!(lp.peers[3].engine.core.ix.grant_overreach.contains(&(id, si)));
    }
    // spec/permissions.md §2: an invite grant's `secrets.0` delta carries only puts of its
    // grantees' boxes. One that also resets a box entry (here one the receiver has not seen yet)
    // or a history box is un-merged at every node whatever the arrival order: validity depends on
    // the delta alone.
    #[test]
    fn invite_grant_resets_unmerged_any_order_spec_perm_2() {
        use osis_crdt::{Op, PathOp, PathSeg};
        use osis_schema::Codec;
        let mut lp = LocalPeer::new(6, 903, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        // 0 admin, 1 invite holder, 2 grantee, 3 and 4 receivers, 5 a holder whose box is reset
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (a, c, e) = (tid(&mut lp, 0), tid(&mut lp, 2), tid(&mut lp, 5));
        let b = tid(&mut lp, 1);
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { invite: Some(Role::Read), ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        // a grant of e the receivers have not seen yet
        let ge = *lp.peers[0].engine.grant(&t, &e, &read).unwrap().commits.last().unwrap();
        let ge = lp.peers[0].engine.package(&ge).unwrap().unwrap();
        lp.deliver(1, &ge).unwrap();
        let s = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let ek = s.boxes.keys().find(|k| k.holder == e).unwrap().clone();
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
            assert_eq!(lp.peers[r].engine.roster(&t).get(&c).map(|x| x.role), Some(Role::Read), "the edge itself is a valid invite grant");
            assert_eq!(lp.peers[r].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), want, "receiver {r}");
        }
    }
    // spec/permissions.md §2, §5.2: an earlier grant on the same edge, arriving late, leaves an
    // invite grant unapplied, its boxes with no exemption: judged again though its author's roles
    // did not move, as where they came in the other order.
    #[test]
    fn invite_grant_overtaken_on_its_edge_any_order_spec_perm_2() {
        let mut lp = LocalPeer::new(5, 971, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        // 0 admin, 1 invite holder, 2 grantee, 3 and 4 receivers
        let (a, b, e) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { invite: Some(Role::Read), ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        let by_admin = *lp.peers[0].engine.grant(&t, &e, &read).unwrap().commits.last().unwrap();
        let by_admin = lp.peers[0].engine.package(&by_admin).unwrap().unwrap();
        lp.advance(1000);
        let id = *lp.peers[1].engine.grant(&t, &e, &read).unwrap().commits.last().unwrap();
        let by_invite = lp.peers[1].engine.package(&id).unwrap().unwrap();
        lp.deliver(3, &by_invite).unwrap();
        assert!(lp.peers[3].engine.edge_write_applied(&t, &id), "applied while alone");
        lp.deliver(3, &by_admin).unwrap();
        lp.deliver(4, &by_admin).unwrap();
        lp.deliver(4, &by_invite).unwrap();
        let secrets = osis_base::Ak::new("secrets.0").unwrap();
        for r in [3, 4] {
            assert!(!lp.peers[r].engine.edge_write_applied(&t, &id), "receiver {r}");
        }
        assert_eq!(lp.peers[3].engine.body_valid(&id, &t, &secrets), lp.peers[4].engine.body_valid(&id, &t, &secrets));
        assert_eq!(lp.peers[3].engine.get_typed(&t, &ct::SECRETS).unwrap(), lp.peers[4].engine.get_typed(&t, &ct::SECRETS).unwrap());
    }
    // spec/permissions.md §2, §5.1 step 4: a late grant makes an invite holder an admin earlier,
    // so its write on another's edge turns from an invite grant (no audit) into an audited write
    // (restores what the holder gave up, demotes): the edge's value is the same, the holder's
    // write falls, as where the grant came first.
    #[test]
    fn invite_grant_turned_audited_any_order_spec_perm_5_1() {
        let mut lp = LocalPeer::new(5, 972, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        // 0 admin, 1 invite holder, 2 holder, 3 and 4 receivers
        let (a, b, h) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let ak = osis_base::Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ak, &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { invite: Some(Role::Read), ..read.clone() }).unwrap();
        lp.peers[0].engine.grant(&t, &h, &ct::Edge { role: Role::Write, ..read.clone() }).unwrap();
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
        // an invite grant at its author, which has heard neither the write nor the rise
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
    // spec/permissions.md §2: an invite grant's `secrets.0` entries are new, created by its own
    // delta. A record claiming the grantee's key at another holder's entry dot would merge into
    // that entry (the stored key wins), overwriting its box: not a put, no invite exemption.
    #[test]
    fn invite_grant_foreign_entry_dot_rejected_spec_perm_2() {
        use osis_crdt::{Batch, Dot, Encoding, SlotRef, Op, PathOp, PathSeg, Source, Writer};
        use osis_schema::Codec;
        fn box_entries(f: &osis_crdt::Fragment) -> Vec<(Dot, Option<Value>)> {
            let Some(SlotRef::Frag(osis_crdt::Fragment::Struct(st))) = f.slot(Encoding::Struct) else { return Vec::new() };
            let Some(SlotRef::Frag(osis_crdt::Fragment::Map(m))) = st.field(0).and_then(|x| x.slot(Encoding::Map)) else { return Vec::new() };
            m.entries().map(|(d, _, k, _)| (d.clone(), k.cloned())).collect()
        }
        let mut lp = LocalPeer::new(3, 904, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b, g) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: Some(Role::Read), tied: None };
        lp.peers[0].engine.grant(&t, &b, &read).unwrap();
        let ak = osis_base::Ak::new("secrets.0").unwrap();
        let st = lp.peers[0].engine.state(&t, &ak).unwrap().unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        // the admin's own box entry
        let (a_dot, a_key) = box_entries(&st).into_iter().find_map(|(d, k)| Some((d, ct::BoxKey::from_value(&k?).ok().filter(|k| k.holder == a)?))).unwrap();
        let bx = s.boxes.get(&a_key).unwrap().clone();
        let g_key = ct::BoxKey { holder: g, role: Role::Read, epoch: a_key.epoch.clone() };
        let schema = osis_schema::core_schema();
        let view = schema.view("secrets.0").unwrap();
        let ts = osis_base::Ts::make(WallMs(1_700_000_000_100), 0).unwrap();
        let mut batch = Batch::new(&st, Writer::new(ts, Source::session(osis_crdt::Session { node: b, nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), 1));
        batch.apply(&PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(g_key.to_value())], op: Op::Put(bx.to_value()) }, &view).unwrap();
        let (d, range) = batch.finish().unwrap();
        let own = crate::engine::Owned::Range { src: Source::session(osis_crdt::Session { node: b, nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), lo: range.lo, hi: range.hi };
        let granted = std::collections::BTreeMap::from([((t, g), Role::Read)]);
        assert!(super::super::validity::grantee_boxes_only(&t, &d, &granted, &own), "an honest put");
        let (g_dot, _) = box_entries(&d).remove(0);
        let mut forged = d.clone();
        forged.map_dots(&|x| (*x == g_dot).then(|| a_dot.clone()));
        assert_eq!(box_entries(&forged).remove(0).0, a_dot);
        assert!(!super::super::validity::grantee_boxes_only(&t, &forged, &granted, &own), "a write into the admin's entry");
    }
    // spec/permissions.md §1: a record chain reaches its key actor within `MAX_CHAIN_DEPTH`
    // links; a delta written on a thing deeper is invalid and the rest of its commit applies, at
    // every node alike. The writer refuses such a commit.
    #[test]
    fn record_chain_deeper_than_cap_invalid_spec_permissions_1() {
        use osis_base::format::MAX_CHAIN_DEPTH;
        let mut lp = LocalPeer::new(3, 905, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let x = osis_base::Ak::new("x:a.0").unwrap();
        let mut up = lp.peers[0].engine.tid();
        let mut shallow = up;
        for i in 0..MAX_CHAIN_DEPTH {
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, up);
            m.set(t, &x, &Value::Int(1)).unwrap();
            lp.peers[0].commit(m).unwrap();
            if i == 0 {
                shallow = t;
            }
            up = t;
        }
        let at_cap = up;
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
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        for r in [0, 1, 2] {
            if r > 0 {
                lp.deliver(r, &pk).unwrap();
            }
            assert_eq!(lp.peers[r].engine.get(&shallow, &x).unwrap(), Some(Value::Int(2)), "peer {r}");
            assert_eq!(lp.peers[r].engine.get(&d, &x).unwrap(), None, "peer {r}");
        }
    }
    // spec/permissions.md §1: the cap counts first-admin links (the record chain), whether the
    // things were made with a write or by their record alone: a chain at `MAX_CHAIN_DEPTH`
    // links applies; one link more is invalid, at the writer and at receivers.
    #[test]
    fn record_chain_through_first_admins_capped_spec_permissions_1() {
        use osis_base::format::MAX_CHAIN_DEPTH;
        let mut lp = LocalPeer::new(2, 906, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let x = osis_base::Ak::new("x:a.0").unwrap();
        let mut up = lp.peers[0].engine.tid();
        for i in 0..MAX_CHAIN_DEPTH {
            let t = if i % 4 == 0 {
                lp.peers[0].engine.create_with_admin(&up).unwrap().0
            } else {
                let mut m = Mutation::new();
                let t = lp.peers[0].engine.new_thing(&mut m, up);
                lp.peers[0].commit(m).unwrap();
                t
            };
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Int(1)).unwrap();
            lp.peers[0].commit(m).unwrap();
            up = t;
        }
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[1].engine.get(&up, &x).unwrap(), Some(Value::Int(1)), "at the cap: applies");
        let mut m = Mutation::new();
        let d = m.create(osis_base::CreationRecord::Thing { admin: up, nonce: [7; 32], link: false });
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
        use osis_perm::HeldSet;
        use osis_schema::Codec;
        let mut lp = LocalPeer::new(2, 906, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let x = lp.peers[1].engine.tid();
        let mut up = me;
        for _ in 0..MAX_CHAIN_DEPTH {
            let mut m = Mutation::new();
            up = lp.peers[0].engine.new_thing(&mut m, up);
            lp.peers[0].commit(m).unwrap();
        }
        let mut m = Mutation::new();
        let shallow = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        let edge_in = |m: &mut Mutation, t: Tid, holder: Tid| {
            m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
        };
        let edge = |t: Tid, holder: Tid| {
            let mut m = Mutation::new();
            edge_in(&mut m, t, holder);
            m
        };
        lp.peers[0].engine.core.skip_writer_rules = true;
        let mut m = Mutation::new();
        let deep = lp.peers[0].engine.new_thing(&mut m, up);
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
    // spec/permissions.md §2: the invite exemption is for an applied invite grant's boxes. A
    // reader pairing its own removal (which always applies) with a put that fails gets no
    // exemption: its boxes for the failed grantee and its history boxes are judged as its own
    // `secrets.0` write (admin), invalid. A redemption-shaped grant by an invite holder stays valid.
    #[test]
    fn self_removal_beside_failing_grant_no_exemption_spec_perm_2() {
        use osis_base::Tid;
        use osis_crdt::{Op, PathOp};
        let mut lp = LocalPeer::new(4, 908, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (a, r, z, g) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &r, &read).unwrap();
        lp.sync_all().unwrap();
        let before = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (rk, rb) = before.boxes.iter().find(|(k, _)| k.holder == r).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let zk = ct::BoxKey { holder: z, role: Role::Admin, epoch: rk.epoch.clone() };
        let hk = ct::HistoryKey { role: Role::Admin, epoch: rk.epoch.clone() };
        let commit = |lp: &mut LocalPeer, who: Tid, edge: ct::Edge, i: usize| {
            let mut m = Mutation::new();
            m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(lp.peers[i].engine.tid())) }).unwrap();
            crate::flows::put_edge(&mut m, t, who, &edge).unwrap();
            let k = ct::BoxKey { holder: who, role: edge.role, ..zk.clone() };
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
            lp.peers[0].engine.core.ix.commits.get(&id).unwrap().valid[si]
        };
        // the reader's self-removal plus a put of z at admin (no authority: fails)
        assert!(!commit(&mut lp, z, ct::Edge { role: Role::Admin, ..read.clone() }, 1), "no exemption beside a failing put");
        assert_eq!(lp.peers[0].engine.roster(&t).get(&z), None);
        assert!(!lp.peers[0].engine.roster(&t).contains_key(&r), "the self-removal applies");
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert!(!s.boxes.contains_key(&zk) && s.history.get(&hk) != Some(&vec![0; 48]));
        // honest shape: an invite holder's grant of g plus its own removal (a redemption)
        lp.peers[0].engine.grant(&t, &z, &ct::Edge { invite: Some(Role::Read), ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        assert!(commit(&mut lp, g, ct::Edge { role: Role::Read, ..read.clone() }, 2), "an applied invite grant's boxes");
        assert_eq!(lp.peers[0].engine.roster(&t).get(&g).map(|e| e.role), Some(Role::Read));
    }
}

mod keys_tests {
    #![allow(clippy::unwrap_used)]
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_base::{Role, Value, WallMs};
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::core_types as ct;
    use osis_schema::Codec;

    // spec/crypto.md §3: "inbox and deposit seed by an admin; a key actor's by its own key". A
    // writer's `keys.0` write of the deposit seed or of a key-actor KEM key is invalid: otherwise a
    // writer (kept valid by its demoter's frontier after removal) set an actor's `key` field and
    // every later grant to the actor was sealed to it.
    #[test]
    fn writer_cannot_write_admin_keys_fields_spec_crypto_3() {
        let mut lp = LocalPeer::new(2, 902, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let w = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Write));
        let before = lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        let kem = lp.peers[1].engine.core.id.keys().kem.public().clone();
        for (field, v) in [(5u64, Some([9u8; 32]).to_value()), (3, Some(ct::KemKey::X25519MlKem768(kem.as_bytes().to_vec())).to_value())] {
            let mut m = Mutation::new();
            m.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(field)], op: Op::Set(v) }).unwrap();
            assert!(lp.peers[1].commit(m.clone()).is_err(), "refused writer-side");
            lp.peers[1].engine.core.skip_writer_rules = true;
            lp.peers[1].commit(m).unwrap().unwrap();
            lp.peers[1].engine.core.skip_writer_rules = false;
        }
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

    // spec/permissions.md §3 (a writer rotates read and write; the admin keyset is an admin's),
    // spec/crypto.md §3: a write or reset of the whole `keys.0` or `secrets.0` value replaces the
    // admin fields and every box: an admin's write, invalid from a writer
    #[test]
    fn writer_cannot_replace_keys_or_secrets_spec_perm_3() {
        let mut lp = LocalPeer::new(2, 903, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let w = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
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
        use osis_crdt::{Batch, Source, Writer};
        let mut lp = LocalPeer::new(2, 905, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let w = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
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
        let mut batch = Batch::new(&st, Writer::new(ts, Source::commit(osis_base::CommitId([7; 32])), 1));
        batch.apply(&PathOp { path: vec![PathSeg::Field(2)], op: Op::Set(Some(forged.clone()).to_value()) }, &view).unwrap();
        let (d, _) = batch.finish().unwrap();
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
        assert!(!lp.peers[0].engine.core.ix.commits.get(&snap).unwrap().valid[0], "a writer's keys.0 snapshot is invalid");
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap(), before);
    }

    // spec/permissions.md §3, spec/crdt.md §5.6: writers W1 and W2 both remove read box X; the
    // admin compacts after W1, drops X's creation and W1's body, then gets W2. A removal carries
    // X's key, so W2 needs the read role wherever it is judged: valid at open, after a rebuild
    // and at every node.
    #[test]
    fn secrets_removal_dropped_creation_open_equals_rebuild() {
        let mut lp = LocalPeer::new(4, 907, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, w1, w2, r) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let we = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &w1, &we).unwrap();
        lp.peers[0].engine.grant(&t, &w2, &we).unwrap();
        let g = *lp.peers[0].engine.grant(&t, &r, &ct::Edge { role: Role::Read, ..we.clone() }).unwrap().commits.last().unwrap();
        lp.sync_all().unwrap();
        let rk = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap().boxes.keys().find(|k| k.holder == r).unwrap().clone();
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
        let v = |lp: &LocalPeer| lp.peers[0].engine.core.ix.commits.get(&c2).unwrap().valid[0];
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
            assert!(lp.peers[i].engine.core.ix.commits.get(&c2).unwrap().valid[0], "peer {i}");
            assert_eq!(lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), want, "peer {i}");
        }
    }

    // spec/crypto.md §4 (Carried: a keyset's rotation commit; held keyset), spec/commits.md §5:
    // admin P rotates read (removing R); the first admin grants X at that epoch, compacts and drops P's
    // rotation bodies. The epoch's introducer stays P's rotation (not the later grant), at open and
    // after a rebuild; the keyset stays held.
    #[test]
    fn dropped_rotation_keeps_its_epoch_intro_spec_crypto_4() {
        let mut lp = LocalPeer::new(4, 931, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, p, r, x) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let e = |role| ct::Edge { role, until: None, invite: None, tied: None };
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
        let mut lp = LocalPeer::new(4, 906, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, w, r) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 3));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
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
        let grant = *lp.peers[0].engine.grant(&t, &r, &ct::Edge { role: Role::Read, until: None, invite: None, tied: None }).unwrap().commits.last().unwrap();
        let grant = lp.peers[0].engine.package(&grant).unwrap().unwrap();
        lp.deliver(1, &grant).unwrap();
        let rk = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap().boxes.keys().find(|k| k.holder == r).unwrap().clone();
        let mut m = Mutation::new();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(rk.to_value()) }).unwrap();
        let id = lp.peers[1].commit(m).unwrap().unwrap();
        let rm = lp.peers[1].engine.package(&id).unwrap().unwrap();
        lp.deliver(2, &rm).unwrap();
        assert!(lp.peers[2].engine.core.ix.commits.get(&id).unwrap().valid[0], "a read box's removal, before the box");
        lp.deliver(2, &grant).unwrap();
        assert!(lp.peers[2].engine.core.ix.commits.get(&id).unwrap().valid[0], "and after it");
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
        let mut lp = LocalPeer::new(2, 908, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let wt = lp.peers[1].engine.tid();
        lp.peers[0].engine.grant(&t, &wt, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let admin = s.boxes.keys().find(|k| k.role == Role::Admin).unwrap().clone();
        let read = ct::BoxKey { role: Role::Read, ..admin.clone() };
        let src = osis_crdt::Source::session(osis_crdt::Session { node: lp.peers[1].engine.tid(), nonce: [0; osis_crdt::SESSION_NONCE_LEN] });
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

    // spec/permissions.md §2: an invite grant carries the grantee's boxes only; a write of the
    // whole `secrets.0` value is no grantee's box
    #[test]
    fn invite_grant_cannot_replace_secrets_spec_perm_2() {
        let mut lp = LocalPeer::new(3, 904, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { role: Role::Read, until: None, invite: Some(Role::Read), tied: None }).unwrap();
        lp.sync_all().unwrap();
        let secrets = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &ct::Edge { role: Role::Read, until: None, invite: None, tied: None }).unwrap();
        m.set(t, &osis_base::Ak::new("secrets.0").unwrap(), &Value::Int(1)).unwrap();
        force(&mut lp, 1, m);
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), secrets);
    }
}
