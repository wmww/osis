//! What a reader of one document fetches in an organisation with members removed, and the size of
//! each removal as a certificate copy. Node 0 makes O and D (O holds write on D: an organisation's hub and
//! one of its documents), writes D, grants `r` member accounts write on O and removes each; node 1
//! is then granted read on D and syncs it for the first time. Counted at two sizes, never timed.

use crate::harness::Step::*;
use crate::harness::history::{Gives, Holder, world_of};
use crate::harness::{World, fixture, play};
use osis_base::CommitId;
use std::collections::BTreeSet;

/// The organisation with `r` members granted and removed, quiet; the removals' and the member
/// grants' commits at node 0.
fn org(r: usize) -> (World, Vec<CommitId>, Vec<CommitId>) {
    let mut grants = vec![];
    let mut removals = vec![];
    let w = fixture(&format!("removal cost org {r}"), || {
        let mut w = world_of(0, 2 + r, 2 + r);
        let _ = play(&mut w, &[New(0), New(0), Give(0, 1, Holder::Thing(0), Gives::Writes), Write(0, 1), Write(0, 1), Run], String::new());
        w
    });
    let mut w = w;
    for j in 0..r {
        for (step, out) in [(Give(0, 0, Holder::Node(2 + j), Gives::Writes), &mut grants), (Revoke(0, 0, Holder::Node(2 + j)), &mut removals)] {
            let before: BTreeSet<CommitId> = w.engine(0).commit_ids().into_iter().collect();
            let label = format!("{step:?}");
            let _ = play(&mut w, &[step], String::new());
            let o = w.history.things[0].0;
            let d = w.history.things[1].0;
            let e = w.engine(0);
            if std::env::var_os("REMOVAL_COST").is_some() {
                for c in e.commit_ids().into_iter().filter(|c| !before.contains(c)) {
                    let h = e.header(&c).unwrap();
                    let asp: Vec<String> = h.aspects.iter().map(|a| format!("{}.{}", if a.tid == o { "O" } else if a.tid == d { "D" } else { "x" }, a.ak.as_str())).collect();
                    let pk = e.package(&c).unwrap();
                    eprintln!("  {label}: {:?} {} B {asp:?}", h.kind, pk.map_or(0, |p| p.bytes.len()));
                }
            }
            let new: Vec<CommitId> = e.commit_ids().into_iter().filter(|c| !before.contains(c) && e.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == o && a.ak.as_str() == "roles.0"))).collect();
            assert_eq!(new.len(), 1, "one role commit on O per step");
            out.push(new[0]);
        }
    }
    let _ = play(&mut w, &[Run], String::new());
    (w, grants, removals)
}

/// A certificate copy of commit `c` projected to its `roles.0` parts on `on`, as node 0 seals it
/// (`Engine::seal_to`): (blob bytes, header bytes, `roles.0` delta bytes).
fn copy_size(w: &mut World, c: &CommitId, on: &osis_base::Tid) -> (usize, usize, usize) {
    let e = w.engine(0);
    let h = e.header(c).unwrap();
    let parts: BTreeSet<usize> = h.aspects.iter().enumerate().filter(|(_, a)| a.tid == *on && a.ak.as_str() == "roles.0").map(|(i, _)| i).collect();
    assert_eq!(parts.len(), 1, "{h:?}");
    let body = e.part_body(c, &parts).unwrap().unwrap();
    let blob = osis_commit::CommitBlob::decode_stored(&body.plaintext).unwrap();
    let delta: usize = blob.parts.iter().map(|p| p.delta.len()).sum();
    let sealed = e.seal_to(&body, osis_blob::Class::Durable, &mut osis_crypto::SeededRng::from_u64(1)).unwrap().unwrap();
    (sealed.blob.len(), h.encode().len(), delta)
}

/// Node 1's first sync of D: bytes every node sent it, and bytes it sent.
fn first_read(w: &mut World) -> (u64, u64) {
    let before = w.net.frames.clone();
    let _ = play(w, &[Grant(0, 1, 1, Gives::Reads), Run], String::new());
    if std::env::var_os("REMOVAL_COST").is_some() {
        for (k, v) in &w.net.frames {
            let b = before.get(k).copied().unwrap_or_default();
            if v.1 != b.1 && (k.0 == 1 || k.1 == 1) {
                eprintln!("  frames {k:?}: {} x, {} B", v.0 - b.0, v.1 - b.1);
            }
        }
    }
    let sum = |f: &std::collections::BTreeMap<(usize, usize, &'static str), (u64, u64)>, to: bool| f.iter().filter(|((a, b, _), _)| if to { *b == 1 && *a != 1 } else { *a == 1 }).map(|(_, v)| v.1).sum::<u64>();
    (sum(&w.net.frames, true) - sum(&before, true), sum(&w.net.frames, false) - sum(&before, false))
}

// Today a removal of a writer from O is carried by every later keyset of O and of each thing O
// reaches (spec/crypto.md §4, Carried demotions: the walk records it on everything the lowered
// edge's target reaches), and a held keyset needs the edge writes of what it carries: a first
// reader of D holds every removal on O, beside D's own rotation for each (the removed member
// could read D through O). Where D requires a removal (evidence of a write it judges)
// it requires it and the grant its reset names as copies, each a role commit's header and its `roles.0` delta on O
// sealed as a copy, measured here. Printed: the first read's bytes at two sizes, each copy's size.
#[test]
#[ignore = "by hand: prints counts (about a minute: six nodes)"]
fn a_reader_of_one_document_holds_every_writer_removal_on_its_hub_today_spec_crypto_4() {
    let (r1, r2) = (1, 4);
    let (mut a, ga, ra) = org(r1);
    let (mut b, _, rb) = org(r2);
    let o = a.history.things[0].0;
    let copies: Vec<(usize, usize, usize)> = ra.iter().chain(&ga).map(|c| copy_size(&mut a, c, &o)).collect();
    let ob = b.history.things[0].0;
    let more: Vec<(usize, usize, usize)> = rb.iter().map(|c| copy_size(&mut b, c, &ob)).collect();
    let (fa, fb) = (first_read(&mut a), first_read(&mut b));
    eprintln!("first read of D: (to reader, from reader) bytes at r = {r1}: {fa:?}, at r = {r2}: {fb:?}: {} B per removal", (fb.0 - fa.0) / (r2 - r1) as u64);
    eprintln!("copies (blob, header, roles.0 delta): the removal and the grant at r = {r1}: {copies:?}; removals at r = {r2}: {more:?}");
    let held = |w: &mut World, cs: &[CommitId]| cs.iter().filter(|c| w.engine(1).header(c).is_some()).count();
    assert_eq!((held(&mut a, &ra), held(&mut a, &ga), held(&mut b, &rb)), (r1, r1, r2), "the reader of D holds each removal on O and the grant it ends");
}
