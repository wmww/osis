//! Which parts of a commit apply and which wait (spec/commits.md §4). Invariant under test: what a
//! node applies is a function of the parts it holds, what else it holds and what it syncs, never
//! of which part came first, however the commit's parts are split over deliveries.

use crate::judgment::observe;
use crate::order::{Played, Rng, Step, play};
use osis_base::{Role, Tid, Value};
use osis_commit::CommitBlob;
use osis_node::{Ingested, Mutation, Reason};
use osis_node::local_peer::Peer;

const SEED: u64 = 1038;
const FRESH: u64 = 0x5eed_f00d;
const SHUFFLES: u64 = 6;

/// One delivery: pack `.0`, whole or only its parts on one thing.
type Tok = (usize, Option<Tid>);

fn reg() -> osis_base::Ak {
    osis_base::Ak::new("t:reg.0").unwrap()
}

/// A history, and what may stay away: packs holding a chain or a creation record.
struct History {
    played: Played,
    /// Whichever of these a case hides, one commit on several things is left without it.
    hides: Vec<Vec<usize>>,
}

fn histories() -> Vec<History> {
    use Step::*;
    let tick = || Advance { who: None, ms: 1000 };
    let content = play(SEED, &[NewTop { by: 0 }, tick(), Edge { by: 0, t: 1, holder: 1, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick(), Two { by: 1, a: 0, b: 1, v: 1 }]);
    let role = play(SEED, &[NewTop { by: 0 }, tick(), Edge { by: 0, t: 1, holder: 2, role: Some(Role::Read) }, Sync { from: 0, to: 2 }, tick(), TwoEdges { by: 2, a: 0, b: 1, holder: 1, role: Role::Read }]);
    let three = play(SEED, &[NewTop { by: 0 }, NewTop { by: 0 }, tick(), Edge { by: 0, t: 1, holder: 1, role: Some(Role::Read) }, Edge { by: 0, t: 2, holder: 1, role: Some(Role::Write) }, Sync { from: 0, to: 1 }, tick(), Three { by: 1, a: 0, b: 1, c: 2, v: 1 }]);
    let honest = play(SEED, &[New { by: 0, parent: 0, write: true }, tick(), Two { by: 0, a: 0, b: 1, v: 7 }]);
    let (cb, rb, tb, hb) = (content.base, role.base, three.base, honest.base);
    vec![
        // no edge, then no creation record
        History { played: content, hides: vec![vec![], vec![cb + 1], vec![cb]] },
        History { played: role, hides: vec![vec![], vec![rb + 1], vec![rb]] },
        History { played: three, hides: vec![vec![], vec![tb + 2], vec![tb + 3], vec![tb + 2, tb + 3], vec![tb]] },
        History { played: honest, hides: vec![vec![], vec![hb]] },
    ]
}

fn part(played: &Played, i: usize, t: Option<Tid>) -> Vec<u8> {
    let pk = &played.packs[i];
    let Some(t) = t else { return pk.bytes.clone() };
    let mut b = CommitBlob::decode(&pk.bytes).unwrap();
    let h = b.header.clone();
    b.parts.retain(|p| h.aspects[p.ai].tid == t);
    b.encode()
}

/// The things pack `i` has parts on.
fn things_of(played: &Played, i: usize) -> Vec<Tid> {
    let b = CommitBlob::decode(&played.packs[i].bytes).unwrap();
    let mut out: Vec<Tid> = b.parts.iter().map(|p| b.header.aspects[p.ai].tid).collect();
    out.dedup();
    out
}

fn deliver(played: &Played, syncs: &[Tid], order: &[Tok]) -> Peer {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    for t in syncs {
        p.engine.set_syncing(*t, true).unwrap();
    }
    for (i, t) in order {
        let _ = p.engine.ingest(&part(played, *i, *t), played.packs[*i].blobs.clone());
    }
    p.engine.reexamine().unwrap();
    p
}

fn seen(played: &Played, p: &mut Peer) -> Vec<(String, String)> {
    let ids = played.packs.iter().map(|x| x.id).collect();
    observe(&mut p.engine, &ids)
}

/// In the order made, each commit whole, but for `hidden`.
fn in_order(played: &Played, hidden: &[usize]) -> Vec<Tok> {
    (0..played.packs.len()).filter(|i| !hidden.contains(i)).map(|i| (i, None)).collect()
}

/// A random order of `hidden`'s complement, multi-thing commits split, some whole copies again.
fn shuffled(played: &Played, hidden: &[usize], rng: &mut Rng) -> Vec<Tok> {
    let mut out: Vec<Tok> = Vec::new();
    for i in (0..played.packs.len()).filter(|i| !hidden.contains(i)) {
        let ts = things_of(played, i);
        if ts.len() > 1 {
            out.extend(ts.into_iter().map(|t| (i, Some(t))));
        } else {
            out.push((i, None));
        }
    }
    for i in (1..out.len()).rev() {
        out.swap(i, rng.below(i as u64 + 1) as usize);
    }
    if rng.below(2) == 0 {
        let at = rng.below(out.len() as u64 + 1) as usize;
        let whole = out[rng.below(out.len() as u64) as usize].0;
        out.insert(at, (whole, None));
    }
    out
}

// spec/requirements.md Decentralization (Deterministic), spec/commits.md §4: for each history,
// held set and sync set, every arrival order and split of the same parts reads alike, whether
// the commit's other things lack an edge or a creation record or nothing, on content and role
// commits and three things.
#[test]
fn split_delivery_any_order_reads_alike_spec_commits_4() {
    for (hi, h) in histories().into_iter().enumerate() {
        let things = h.played.things.clone();
        let syncs: Vec<Vec<Tid>> = vec![vec![], vec![things[1]], vec![things[0], things[1]]];
        for hidden in &h.hides {
            for sy in &syncs {
                let want = seen(&h.played, &mut deliver(&h.played, sy, &in_order(&h.played, hidden)));
                let mut rng = Rng(hi as u64 + 1);
                for n in 0..SHUFFLES {
                    let order = shuffled(&h.played, hidden, &mut rng);
                    let got = seen(&h.played, &mut deliver(&h.played, sy, &order));
                    if got != want {
                        let first = got.iter().zip(&want).find(|(a, b)| a != b);
                        panic!("history {hi}, hidden {hidden:?}, syncs {}, shuffle {n}, order {order:?}: {first:?}", sy.len());
                    }
                }
            }
        }
    }
}

/// `played`'s last commit's value on a thing, delivered with the packs `hidden` held back.
fn reads(played: &Played, syncs: &[Tid], hidden: &[usize]) -> (Vec<Option<Value>>, usize) {
    let mut p = deliver(played, syncs, &in_order(played, hidden));
    let r = played.things.iter().map(|t| p.engine.get(t, &reg()).unwrap()).collect();
    (r, p.engine.pending().len())
}

fn v(x: &str) -> Option<Value> {
    Some(Value::Str(x.into()))
}

// spec/commits.md §4: a part on a thing the node does not sync, its chain away, waits alone and
// the rest applies; once the thing is synced the commit waits whole; a chain arriving later ends
// in-order's state (`split_delivery_*` compares every order to it). Three things: only the chainless
// part waits.
#[test]
fn chainless_part_waits_alone_unless_synced_spec_commits_4() {
    let hs = histories();
    let (content, three) = (&hs[0].played, &hs[2].played);
    let (g, h) = (content.things[0], content.things[1]);
    let edge = content.base + 1;
    let (got, pending) = reads(content, &[], &[edge]);
    assert_eq!((got[0].clone(), got[1].clone(), pending), (v("v1"), v("top"), 1), "unsynced: G applied, H waits");
    let (got, pending) = reads(content, &[h], &[edge]);
    assert_eq!((got[0].clone(), got[1].clone(), pending), (v("g"), v("top"), 1), "H synced: nothing of it shows");
    let (got, pending) = reads(content, &[g, h], &[]);
    assert_eq!((got[0].clone(), got[1].clone(), pending), (v("v1"), v("top"), 0), "the chain held: 1 only reads H, its write there judged invalid");
    let (g3, h3, c3) = (three.things[0], three.things[1], three.things[2]);
    let (got, pending) = reads(three, &[], &[three.base + 2]);
    assert_eq!(got, vec![v("v1"), v("top"), v("v1")], "{g3} {h3} {c3}: only H's part waits");
    assert_eq!(pending, 1);
    let (got, _) = reads(three, &[h3], &[three.base + 2]);
    assert_eq!(got, vec![v("g"), v("top"), v("top")], "H synced: the commit waits whole");
    let (got, _) = reads(three, &[c3], &[three.base + 2]);
    assert_eq!(got, vec![v("v1"), v("top"), v("v1")], "C synced, its chain held: only H's part waits");
}

// spec/commits.md §4: a role commit's parts always wait alone, so what it does to one thing's
// roster reads alike however the other part came and whichever things are synced: authority does
// not depend on the sync set.
#[test]
fn role_part_applies_whatever_is_synced_spec_commits_4() {
    let hs = histories();
    let role = &hs[1].played;
    let (g, h) = (role.things[0], role.things[1]);
    let roster = |p: &mut Peer| seen(role, p).into_iter().find(|(k, _)| *k == format!("thing {g}")).unwrap().1;
    let edge = role.base + 1;
    let before: Vec<usize> = (0..role.packs.len() - 1).collect();
    let mut was = deliver(role, &[], &before.iter().filter(|i| **i != edge).map(|i| (*i, None)).collect::<Vec<_>>());
    let was = roster(&mut was);
    let order = in_order(role, &[edge]);
    let mut applied = deliver(role, &[], &order);
    let applied = roster(&mut applied);
    assert_ne!(applied, was, "the G part applies");
    for sy in [vec![h], vec![g], vec![g, h]] {
        assert_eq!(roster(&mut deliver(role, &sy, &order)), applied, "{sy:?}");
    }
}

/// Peer 0's commit `write` makes on two of its things peer 1 knows, split per thing.
fn two_things(seed: u64, write: impl Fn(&mut Mutation, Tid, Tid)) -> (osis_node::local_peer::LocalPeer, Tid, Tid, osis_node::local_peer::Package) {
    use crate::common::*;
    let mut lp = net(2, seed);
    let (g, h) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    for pk in packages(&mut lp, 0) {
        lp.deliver(1, &pk).unwrap();
    }
    let mut m = Mutation::new();
    write(&mut m, g, h);
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    (lp, g, h, pk)
}

fn on(pk: &osis_node::local_peer::Package, t: Tid) -> Vec<u8> {
    let mut b = CommitBlob::decode(&pk.bytes).unwrap();
    let h = b.header.clone();
    b.parts.retain(|p| h.aspects[p.ai].tid == t);
    b.encode()
}

// spec/commits.md §4, §8: a paged part whose pages are away is one more wait of its thing: alone
// when not synced, in either order, and it joins when they come; the commit waits whole when
// synced.
#[test]
fn part_missing_pages_waits_like_a_chainless_one_spec_commits_4() {
    use crate::common::*;
    let map: std::collections::BTreeMap<Value, Value> = (0..2000).map(|i| (Value::Str(format!("key {i:05}")), Value::Str("v".repeat(60)))).collect();
    let big = Value::Map(map);
    for (first_g, synced) in [(true, false), (false, false), (true, true), (false, true)] {
        let want = big.clone();
        let (mut lp, g, h, pk) = two_things(61, |m, g, h| {
            m.set(g, &REG, &s("small")).unwrap();
            m.set(h, &BIG, &want).unwrap();
        });
        assert!(!pk.blobs.is_empty(), "paged");
        let e = &mut lp.peers[1].engine;
        if synced {
            e.set_syncing(h, true).unwrap();
        }
        for t in if first_g { [g, h] } else { [h, g] } {
            let _ = e.ingest(&on(&pk, t), Vec::new());
        }
        e.reexamine().unwrap();
        assert_eq!(e.get(&g, &ak("t:reg.0")).unwrap() == Some(s("small")), !synced, "first_g {first_g} synced {synced}");
        assert_eq!(e.pending(), vec![(pk.id, Reason::WaitBlobs)]);
        assert_eq!(e.get(&h, &ak("t:big.0")).unwrap(), None);
        e.put_blobs(pk.blobs.clone()).unwrap();
        e.reexamine().unwrap();
        assert!(e.pending().is_empty(), "{:?}", e.pending());
        assert_eq!(e.get(&g, &ak("t:reg.0")).unwrap(), Some(s("small")));
        assert_eq!(e.get(&h, &ak("t:big.0")).unwrap(), Some(big.clone()));
    }
}

// spec/versioning.md §2, spec/commits.md §4: a parked part on a thing not synced waits alone,
// together or split, either order, and is kept to relay; synced, it parks the commit whole, its
// other part kept with it.
#[test]
fn parked_part_waits_like_a_chainless_one_spec_versioning_2() {
    use crate::common::*;
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Writer, create, encode_delta};
    let mut lp = net(2, 62);
    let (g, h) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    for pk in packages(&mut lp, 0) {
        lp.deliver(1, &pk).unwrap();
    }
    lp.peers[0].clock.advance(10);
    let e = &mut lp.peers[0].engine;
    let recs = vec![e.get_typed(&g, &osis_schema::core_types::CREATED).unwrap().unwrap(), e.get_typed(&h, &osis_schema::core_types::CREATED).unwrap().unwrap()];
    let author = e.tid();
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    let form = crate::common::forged_session(author);
    let mut w = Writer::new(ts, form.own_source(author, osis_base::CommitId([0; 32])), 1000);
    let view = osis_crdt::AnyView;
    let f = create(&mut w, &view, &s("ok")).unwrap();
    let r = w.range();
    let good = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, Kind::Content, ts, author, r.lo, r.hi), None).unwrap();
    let parked = osis_base::encode(&Value::List(vec![Value::Bytes(vec![0; 16]), Value::List(vec![]), Value::List(vec![]), Value::List(vec![Value::Int(99)])]));
    let mut cb = CommitBuilder::new(Kind::Content, ts, author, author, form);
    cb.aspects.push(AspectWrite::new(g, ak("t:reg.0"), r.lo, r.hi, good));
    cb.aspects.push(AspectWrite::new(h, ak("t:future.0"), 100, 101, parked));
    let blob = cb.build(&e.identity().keys().signing, &crate::receive::Dedup(recs), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(1)).unwrap().commit;
    let part = |t: Tid| {
        let mut b = blob.clone();
        let hd = b.header.clone();
        b.parts.retain(|p| hd.aspects[p.ai].tid == t);
        b.encode()
    };
    let id = blob.id();
    let e = &mut lp.peers[1].engine;
    let r = e.ingest(&part(h), Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Parked(_)), "{r:?}");
    e.set_syncing(h, true).unwrap();
    let _ = e.ingest(&part(g), Vec::new());
    e.reexamine().unwrap();
    assert_eq!(e.get(&g, &ak("t:reg.0")).unwrap(), Some(s("new")), "synced: parked whole");
    let held = CommitBlob::decode(&e.commit_bytes(&id).unwrap().unwrap()).unwrap();
    assert_eq!(held.parts.len(), 2, "the parked part kept with the other");
    e.set_syncing(h, false).unwrap();
    e.reexamine().unwrap();
    assert_eq!(e.get(&g, &ak("t:reg.0")).unwrap(), Some(s("ok")), "not synced: the rest applies");
    assert_eq!(e.pending(), vec![(id, Reason::Parked)], "the parked part stays");
    // the same from the other order, and together
    let (mut other, mut together) = (net(2, 62), net(2, 62));
    for lp2 in [&mut other, &mut together] {
        for pk in packages(&mut lp, 0) {
            lp2.deliver(1, &pk).unwrap();
        }
    }
    let _ = other.peers[1].engine.ingest(&part(g), Vec::new());
    let _ = other.peers[1].engine.ingest(&part(h), Vec::new());
    let _ = together.peers[1].engine.ingest(&blob.encode(), Vec::new());
    for x in [&mut other, &mut together] {
        assert_eq!(x.peers[1].engine.get(&g, &ak("t:reg.0")).unwrap(), Some(s("ok")));
        assert_eq!(x.peers[1].engine.pending(), vec![(id, Reason::Parked)]);
    }
}

// spec/commits.md §4, §5: a part under keep at most 0 whose thing's record is away, a later write
// on it superseding it: in every order of its parts, the later commit and the record, and synced or
// not, the node reads alike, past the kill included (`apply::at_most_bound`).
#[test]
fn chainless_part_under_at_most_any_order_spec_commits_4() {
    use crate::common::*;
    let mut lp = net(2, 63);
    let g = new_thing(&mut lp, 0);
    let setup = packages(&mut lp, 0);
    let h = new_thing(&mut lp, 0);
    let made = packages(&mut lp, 0);
    let record: Vec<_> = made.into_iter().filter(|p| !setup.iter().any(|x| x.id == p.id)).collect();
    lp.peers[0].clock.advance(10);
    let mut m = Mutation::new();
    m.set(g, &REG, &s("one")).unwrap();
    m.set(h, &GONE, &s("x")).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].clock.advance(10);
    let mut m = Mutation::new();
    m.set(h, &GONE, &s("y")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    let all = packages(&mut lp, 0);
    let (p1, p2) = (all.iter().find(|p| p.id == c1).unwrap(), all.iter().find(|p| p.id == c2).unwrap());
    let mut toks: Vec<Vec<Vec<u8>>> = record.iter().map(|p| vec![p.bytes.clone()]).collect();
    toks.push(vec![on(p1, g)]);
    toks.push(vec![on(p1, h)]);
    toks.push(vec![p2.bytes.clone()]);
    let now = lp.peers[0].engine.now();
    let ids: std::collections::BTreeSet<_> = all.iter().map(|p| p.id).collect();
    for syncs in [vec![], vec![h]] {
        let mut want = None;
        for perm in permutations(toks.len()) {
            let mut p = Peer::new(FRESH, now).unwrap();
            for t in &syncs {
                p.engine.set_syncing(*t, true).unwrap();
            }
            for x in setup.iter().map(|p| &p.bytes) {
                let _ = p.engine.ingest(x, Vec::new());
            }
            for i in &perm {
                for b in &toks[*i] {
                    let _ = p.engine.ingest(b, Vec::new());
                }
            }
            p.engine.reexamine().unwrap();
            let got = observe(&mut p.engine, &ids);
            let w = want.get_or_insert_with(|| got.clone());
            let first = got.iter().zip(w.iter()).find(|(a, b)| a != b);
            assert!(got == *w, "syncs {}, order {perm:?}: {first:?}", syncs.len());
            assert_eq!(p.engine.get(&g, &ak("t:reg.0")).unwrap(), Some(s("one")));
            assert_eq!(p.engine.get(&h, &ak("t:gone.0")).unwrap(), Some(s("y")));
        }
    }
}

// issues/body-class-moves.md: one body under keep at most 0 on G and H, H's record away, a later
// commit killing G's write. With the record first G's body stays (H's write is live); with it last
// G's part was a body alone with no live write, so it dropped.
#[test]
#[ignore = "known hole: issues/body-class-moves.md"]
fn repro_body_class_move_drops_spec_commits_5() {
    use crate::common::*;
    let mut lp = net(2, 63);
    let g = new_thing(&mut lp, 0);
    let setup = packages(&mut lp, 0);
    let h = new_thing(&mut lp, 0);
    let made = packages(&mut lp, 0);
    let record: Vec<_> = made.into_iter().filter(|p| !setup.iter().any(|x| x.id == p.id)).collect();
    lp.peers[0].clock.advance(10);
    let mut m = Mutation::new();
    m.set(g, &GONE, &s("x")).unwrap();
    m.set(h, &GONE, &s("x")).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].clock.advance(10);
    let mut m = Mutation::new();
    m.set(g, &GONE, &s("y")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    let all = packages(&mut lp, 0);
    let (p1, p2) = (all.iter().find(|p| p.id == c1).unwrap(), all.iter().find(|p| p.id == c2).unwrap());
    let now = lp.peers[0].engine.now();
    let ids: std::collections::BTreeSet<_> = all.iter().map(|p| p.id).collect();
    let mut want = None;
    for record_first in [true, false] {
        let mut p = Peer::new(FRESH, now).unwrap();
        for x in &setup {
            let _ = p.engine.ingest(&x.bytes, Vec::new());
        }
        let rec = |p: &mut Peer| {
            for x in &record {
                let _ = p.engine.ingest(&x.bytes, Vec::new());
            }
        };
        if record_first {
            rec(&mut p);
        }
        let _ = p.engine.ingest(&p1.bytes, Vec::new());
        let _ = p.engine.ingest(&p2.bytes, Vec::new());
        rec(&mut p);
        p.engine.reexamine().unwrap();
        let got = observe(&mut p.engine, &ids);
        let w = want.get_or_insert_with(|| got.clone());
        let first = got.iter().zip(w.iter()).find(|(a, b)| a != b);
        assert!(got == *w, "record first {record_first}: {first:?}");
    }
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    let mut out = vec![vec![]];
    for i in 0..n {
        out = out.into_iter().flat_map(|p: Vec<usize>| (0..=p.len()).map(move |at| { let mut q = p.clone(); q.insert(at, i); q }).collect::<Vec<_>>()).collect();
    }
    out
}

// spec/commits.md §4, spec/crypto.md §4: a part waiting alone is pending like a whole commit: its
// boxes are read, in either order, since they may open what it waits for.
#[test]
fn waiting_parts_boxes_are_read_in_either_order_spec_crypto_4() {
    use crate::common::*;
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    use osis_schema::{Codec, core_types as ct};
    let mut lp = net(2, 64);
    let g = new_thing(&mut lp, 0);
    let known = packages(&mut lp, 0);
    let h = new_thing(&mut lp, 0);
    let rcpt = read_recipient(&lp.peers[1].engine);
    let e = &mut lp.peers[0].engine;
    let recs = vec![e.get_typed(&g, &ct::CREATED).unwrap().unwrap(), e.get_typed(&h, &ct::CREATED).unwrap().unwrap()];
    let recs2 = recs.clone();
    let mut held = osis_keys::ActorEpochs::default();
    held.read.set_established(osis_keys::Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
    let rot = osis_keys::rotate(&h, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &osis_keys::Names::default(), &mut osis_crypto::SeededRng::from_u64(5)).unwrap();
    let boxed = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
    let secrets = osis_base::Ak::new("secrets.0").unwrap();
    let author = e.tid();
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    let view = osis_schema::core_schema().view(secrets.as_str()).unwrap();
    let mut w = Writer::new(ts, Source::commit(osis_base::CommitId([0; 32])), 1);
    let f = create(&mut w, &view, &boxed).unwrap();
    let r = w.range();
    let cx = writer_ctx(Form::Commit, Kind::Role, ts, author, r.lo, r.hi);
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, author, author, Form::Commit);
    for t in [g, h] {
        let mut aw = AspectWrite::new(t, secrets.clone(), r.lo, r.hi, bytes.clone());
        aw.retention = osis_commit::retention::write_retention(secrets.as_str(), None, None).unwrap();
        cb.aspects.push(aw);
    }
    let blob = cb.build(&e.identity().keys().signing, &crate::receive::Dedup(recs), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit;
    let part = |t: Tid| {
        let mut b = blob.clone();
        let hd = b.header.clone();
        b.parts.retain(|p| hd.aspects[p.ai].tid == t);
        b.encode()
    };
    let (one, two, whole) = (part(g), part(h), blob.encode());
    let plain = {
        // G's part is no `secrets.0`: only the waiting part's boxes can be read
        let mut cb = CommitBuilder::new(Kind::Role, ts, author, author, Form::Commit);
        let lab = osis_base::Ak::new("label.0").unwrap();
        for (t, a) in [(g, &lab), (h, &secrets)] {
            let mut aw = AspectWrite::new(t, a.clone(), r.lo, r.hi, bytes.clone());
            aw.retention = osis_commit::retention::write_retention(a.as_str(), None, None).unwrap();
            cb.aspects.push(aw);
        }
        cb.build(&lp.peers[0].engine.identity().keys().signing, &crate::receive::Dedup(recs2), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit
    };
    let plain_id = plain.id();
    let plain = plain.encode();
    // a relay's junk in H's slot first: the true copy's boxes are read though the junk keeps the slot
    let junk_two = with_delta(&two, 3, 40);
    for (name, id, order) in [("G first", blob.id(), vec![&one, &two]), ("H first", blob.id(), vec![&two, &one]), ("together", blob.id(), vec![&whole]), ("plain G part", plain_id, vec![&plain]), ("junk first", blob.id(), vec![&junk_two, &two, &one])] {
        let mut lp2 = net(2, 64);
        for pk in &known {
            lp2.deliver(1, pk).unwrap();
        }
        let e = &mut lp2.peers[1].engine;
        for b in order {
            let _ = e.ingest(b, Vec::new());
        }
        e.reexamine().unwrap();
        assert_eq!(e.pending().len(), 1, "H's part waits for H's record");
        assert!(e.commit_ids().contains(&id), "{name}: G's part applied");
        assert!(!e.lost_due(), "{name}: nothing forgotten for it");
        assert!(e.epochs(&h).is_some_and(|x| x.read.holds_any()), "{name}: the waiting part's box read");
    }
}

// spec/commits.md §4: an applied commit holds nothing back: a late part joins whether or not a
// thing synced since has a wait or another part is missing.
#[test]
fn late_part_of_applied_commit_joins_alone_spec_commits_4() {
    let hs = histories();
    let three = &hs[2].played;
    let (g, h, c) = (three.things[0], three.things[1], three.things[2]);
    let last = three.packs.len() - 1;
    let setup: Vec<Tok> = in_order(three, &[last]);
    for (hidden, syncs) in [(vec![three.base + 2], vec![h]), (vec![], vec![h, c])] {
        let mut order: Vec<Tok> = setup.iter().filter(|x| !hidden.contains(&x.0)).copied().collect();
        order.push((last, Some(g)));
        let mut p = deliver(three, &[], &order);
        for t in &syncs {
            p.engine.set_syncing(*t, true).unwrap();
        }
        let _ = p.engine.ingest(&part(three, last, Some(c)), Vec::new());
        p.engine.reexamine().unwrap();
        assert_eq!(p.engine.get(&c, &reg()).unwrap(), v("v1"), "hidden {hidden:?}");
    }
}

// spec/commits.md §4: a part that hashes to its entry but does not decode is dropped alone, however
// the parts arrive.
#[test]
fn bad_part_together_or_split_spec_commits_4() {
    use crate::common::*;
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Writer, create, encode_delta};
    let mut lp = net(2, 65);
    let (g, h) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let setup = packages(&mut lp, 0);
    lp.peers[0].clock.advance(10);
    let e = &mut lp.peers[0].engine;
    let recs = vec![e.get_typed(&g, &osis_schema::core_types::CREATED).unwrap().unwrap(), e.get_typed(&h, &osis_schema::core_types::CREATED).unwrap().unwrap()];
    let author = e.tid();
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    let form = crate::common::forged_session(author);
    let mut w = Writer::new(ts, form.own_source(author, osis_base::CommitId([0; 32])), 1000);
    let f = create(&mut w, &osis_crdt::AnyView, &s("ok")).unwrap();
    let r = w.range();
    let good = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, Kind::Content, ts, author, r.lo, r.hi), None).unwrap();
    let bad = osis_base::encode(&Value::List(vec![Value::Int(1)]));
    let mut cb = CommitBuilder::new(Kind::Content, ts, author, author, form);
    cb.aspects.push(AspectWrite::new(g, ak("t:reg.0"), r.lo, r.hi, good));
    cb.aspects.push(AspectWrite::new(h, ak("t:reg.0"), 100, 101, bad));
    let blob = cb.build(&e.identity().keys().signing, &crate::receive::Dedup(recs), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(1)).unwrap().commit;
    let read = |deliveries: Vec<Vec<u8>>| {
        let mut lp2 = net(2, 65);
        for pk in &setup {
            lp2.deliver(1, pk).unwrap();
        }
        for b in &deliveries {
            let _ = lp2.peers[1].engine.ingest(b, Vec::new());
        }
        lp2.peers[1].engine.get(&g, &ak("t:reg.0")).unwrap()
    };
    let part = |t: Tid| {
        let mut b = blob.clone();
        let hd = b.header.clone();
        b.parts.retain(|p| hd.aspects[p.ai].tid == t);
        b.encode()
    };
    assert_eq!(read(vec![blob.encode()]), read(vec![part(g), part(h)]));
}

// spec/commits.md §4: a part bad by itself beside its thing's other parts, one away. Its author stalls
// only that commit: nothing of the thing's content shows, another commit on the thing does, a junk copy
// of the bad slot changes nothing; when the last part comes, the good parts apply in every order, synced
// or not, as from the whole blob.
#[test]
fn bad_part_under_a_unit_wait_stalls_only_its_commit_spec_commits_4() {
    use crate::common::*;
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Writer, create, encode_delta};
    let mut lp = net(2, 66);
    let g = new_thing(&mut lp, 0);
    let setup = packages(&mut lp, 0);
    lp.peers[0].clock.advance(10);
    let e = &mut lp.peers[0].engine;
    let recs = vec![e.get_typed(&g, &osis_schema::core_types::CREATED).unwrap().unwrap()];
    let author = e.tid();
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    let form = crate::common::forged_session(author);
    let own = form.own_source(author, osis_base::CommitId([0; 32]));
    let delta = |text: &str, nonce: u8, at: u64| {
        let mut w = Writer::new(ts, own.clone(), at);
        let f = create(&mut w, &osis_crdt::AnyView, &s(text)).unwrap();
        let r = w.range();
        let cx = writer_ctx(form, Kind::Content, ts, author, r.lo, r.hi);
        (encode_delta(&Delta { nonce: [nonce; 16], fragment: f }, &cx, None).unwrap(), r.lo, r.hi)
    };
    let (one, two) = (delta("one", 7, 1000), delta("two", 8, 1000));
    let bad = osis_base::encode(&Value::List(vec![Value::Int(1)]));
    let mut cb = CommitBuilder::new(Kind::Content, ts, author, author, form);
    cb.aspects.push(AspectWrite::new(g, ak("t:one.0"), one.1, one.2, one.0));
    cb.aspects.push(AspectWrite::new(g, ak("t:two.0"), two.1, two.2, two.0));
    cb.aspects.push(AspectWrite::new(g, ak("t:bad.0"), 100, 101, bad));
    let blob = cb.build(&e.identity().keys().signing, &crate::receive::Dedup(recs), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(1)).unwrap().commit;
    let id = blob.id();
    lp.peers[0].clock.advance(10);
    let mut m = Mutation::new();
    m.set(g, &REG, &s("beside")).unwrap();
    let beside = lp.peers[0].commit(m).unwrap().unwrap();
    let beside = packages(&mut lp, 0).into_iter().find(|p| p.id == beside).unwrap();
    let on = |key: &str| {
        let mut b = blob.clone();
        let h = b.header.clone();
        b.parts.retain(|p| h.aspects[p.ai].ak.as_str() == key);
        b.encode()
    };
    let (p_one, p_two, p_bad) = (on("t:one.0"), on("t:two.0"), on("t:bad.0"));
    let read = |synced: bool, deliveries: &[&[u8]]| {
        let mut lp2 = net(2, 66);
        for pk in &setup {
            lp2.deliver(1, pk).unwrap();
        }
        let e = &mut lp2.peers[1].engine;
        if synced {
            e.set_syncing(g, true).unwrap();
        }
        for b in deliveries {
            let _ = e.ingest(b, Vec::new());
        }
        e.reexamine().unwrap();
        (e.get(&g, &ak("t:one.0")).unwrap(), e.get(&g, &ak("t:two.0")).unwrap(), e.commit_ids().contains(&id), e.pending())
    };
    for synced in [false, true] {
        let got = read(synced, &[&blob.encode()]);
        assert_eq!((&got.0, &got.1, got.2), (&Some(s("one")), &Some(s("two")), true), "synced {synced}");
        assert!(got.3.is_empty());
        let parts = [&p_one[..], &p_two[..], &p_bad[..]];
        for order in permutations(3) {
            let seq: Vec<&[u8]> = order.iter().map(|i| parts[*i]).collect();
            assert_eq!(read(synced, &seq), got, "synced {synced}, order {order:?}");
            // the first two alone: the commit waits, nothing of it shows
            let held = read(synced, &seq[..2]);
            let bad_only_left = order[2] == 2;
            if !bad_only_left {
                assert_eq!((&held.0, &held.1, held.2), (&None, &None, false), "synced {synced}, held {:?}", &order[..2]);
            }
            assert_eq!(held.3, vec![(id, Reason::WaitDeltas)], "synced {synced}, held {:?}", &order[..2]);
        }
        // a junk copy of the bad slot: refused, the stored copy stays, and the rest comes
        let mut lp2 = net(2, 66);
        for pk in &setup {
            lp2.deliver(1, pk).unwrap();
        }
        if synced {
            lp2.peers[1].engine.set_syncing(g, true).unwrap();
        }
        let e = &mut lp2.peers[1].engine;
        let r = e.ingest(&p_bad, Vec::new()).unwrap();
        assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
        let mut junk = CommitBlob::decode(&p_bad).unwrap();
        junk.parts[0].delta = osis_base::encode(&Value::List(vec![Value::Int(2)]));
        assert!(e.ingest(&junk.encode(), Vec::new()).is_ok_and(|x| matches!(x, Ingested::Pending(..))) || e.pending().len() == 1);
        assert!(e.take_redeliver().is_empty(), "the stored copy was checked: it kept nothing out");
        // another commit on the thing shows
        lp2.deliver(1, &beside).unwrap();
        let e = &mut lp2.peers[1].engine;
        assert_eq!(e.get(&g, &ak("t:reg.0")).unwrap(), Some(s("beside")));
        e.ingest(&p_one, Vec::new()).unwrap();
        assert_eq!(e.get(&g, &ak("t:one.0")).unwrap(), None);
        e.ingest(&p_two, Vec::new()).unwrap();
        assert_eq!(e.get(&g, &ak("t:one.0")).unwrap(), Some(s("one")));
        assert_eq!(e.get(&g, &ak("t:bad.0")).unwrap(), None);
        assert!(e.pending().is_empty(), "{:?}", e.pending());
    }
}

// Reviewer's differential: random histories with role commits granting across things, commits on
// three things and hostile spans; every part split by aspect, in random orders. Each fixed sync set
// and hidden set must read alike. With a sync set that changes during delivery, content may differ
// (issues/sync-learned-after-apply.md); rosters may not (`role_part_applies_whatever_is_synced`).
fn diff_steps(rng: &mut Rng) -> Vec<Step> {
    use Step::*;
    let aim = |s: Step| Aim(Box::new(s));
    let mut out = vec![NewTop { by: 0 }, NewTop { by: 0 }, Advance { who: None, ms: 1000 }];
    for _ in 0..(8 + rng.below(14)) {
        let (a, b, c) = (rng.below(5) as usize, rng.below(5) as usize, rng.below(5) as usize);
        let by = rng.below(3) as usize;
        let holder = rng.pick(&[1, 2]);
        out.push(match rng.below(17) {
            0 | 1 => aim(Edge { by: 0, t: a, holder, role: rng.pick(&[None, Some(Role::Read), Some(Role::Write), Some(Role::Admin)]) }),
            2 => aim(New { by: 0, parent: a, write: rng.below(2) == 0 }),
            3 => Forged { by, a, b, how: 1, op: rng.below(30) as u8, k: 0, v: rng.below(9) as u8 },
            4 | 5 => Forged { by, a, b, how: 2, op: 0, k: 0, v: rng.below(9) as u8 },
            6 => Forged { by, a, b, how: 3, op: 0, k: 0, v: 0 },
            7 => Forged { by, a, b, how: 4, op: 0, k: 0, v: 0 },
            8 => {
                let from = rng.below(3) as usize;
                Sync { from, to: (from + 1 + rng.below(2) as usize) % 3 }
            }
            9 => Send { from: by, to: holder, back: rng.below(3) as u8 },
            10 => Three { by: 0, a: a % 3, b: (a + 1) % 3, c: (a + 2) % 3, v: c as u8 },
            11 => aim(Demote { by: 0, t: a, holder, at: rng.below(4) as u8, to_read: rng.below(2) == 0 }),
            12 => aim(Roster { by: 0, t: a }),
            13 => BadPart { by, a, b, how: rng.below(4) as u8 },
            14 => BigDemote { by: 0, t: a, holder },
            15 => Roster { by: 0, t: a },
            _ => Advance { who: None, ms: 1000 },
        });
    }
    // a linked frontier for the variants that keep its blobs away
    let holder = rng.pick(&[1, 2]);
    out.extend([BadPart { by: 0, a: 0, b: 1, how: rng.below(4) as u8 }, Advance { who: None, ms: 1000 }, BigDemote { by: 0, t: 0, holder }, Advance { who: None, ms: 1000 }, Roster { by: 0, t: 0 }]);
    out
}

/// What a relay can make of pack `i`: the same signed header with another's deltas in its slots, or
/// with another's signature, or both.
fn junk_copy(played: &Played, i: usize, rng: &mut Rng) -> Vec<u8> {
    let mut b = CommitBlob::decode(&played.packs[i].bytes).unwrap();
    let other = CommitBlob::decode(&played.packs[rng.below(played.packs.len() as u64) as usize].bytes).unwrap();
    let how = rng.below(3);
    if how != 0 {
        for p in &mut b.parts {
            p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![rng.below(256) as u8; 40]), Value::Int(i as i64)]));
        }
    }
    if how != 1 {
        b.signature = other.signature;
    }
    b.encode()
}

/// What a node keeps of what it is given, for the tests here at the engine: every copy, ingested again
/// as `SyncEngine::redeliver` does but for its look at which slots a copy brings (`parts_relay` runs the
/// real one, restarts and lost names included).
#[derive(Default)]
struct Relay {
    copies: Vec<(CommitBlob, Vec<u8>)>,
    /// Copies ingested again.
    again: usize,
}

impl Relay {
    fn give(&mut self, p: &mut Peer, bytes: &[u8], blobs: Vec<(osis_base::BlobId, Vec<u8>)>) {
        let c = CommitBlob::decode(bytes).unwrap();
        let _ = p.engine.ingest(bytes, blobs);
        self.copies.push((c, bytes.to_vec()));
        self.settle(p);
    }
    fn settle(&mut self, p: &mut Peer) {
        p.engine.reexamine().unwrap();
        for _ in 0..=self.copies.len() {
            let names = p.engine.take_redeliver();
            if names.is_empty() {
                return;
            }
            for c in names {
                for (b, bytes) in &self.copies {
                    if b.id() == c && p.engine.parts_genuine(b) != Some(false) {
                        self.again += 1;
                        let _ = p.engine.ingest(bytes, Vec::new());
                    }
                }
            }
            p.engine.reexamine().unwrap();
        }
        assert!(p.engine.take_redeliver().is_empty(), "a name for every round");
    }
}

/// Pack `i` cut into parts by aspect.
fn cuts(played: &Played, i: usize) -> Vec<Vec<u8>> {
    let b = CommitBlob::decode(&played.packs[i].bytes).unwrap();
    let ais: std::collections::BTreeSet<usize> = b.parts.iter().map(|p| p.ai).collect();
    if ais.len() < 2 {
        return vec![played.packs[i].bytes.clone()];
    }
    ais.into_iter()
        .map(|ai| {
            let mut x = b.clone();
            x.parts.retain(|p| p.ai == ai);
            x.encode()
        })
        .collect()
}

/// What one seed of `parts_differential` held and found.
#[derive(Default)]
struct PartsSeed {
    played: bool,
    bad_parts: usize,
    linked: usize,
    bad: Vec<String>,
}

fn parts_seed(seed: u64) -> PartsSeed {
    let mut bad = Vec::new();
    let (mut bad_parts, mut linked) = (0, 0);
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let steps = diff_steps(&mut rng);
    // a scripted step may be refused after a demotion
    let Ok(played) = std::panic::catch_unwind(|| play(seed, &steps)) else { return PartsSeed::default() };
    for pk in &played.packs {
        let b = CommitBlob::decode(&pk.bytes).unwrap();
        linked += usize::from(b.header.kind == osis_commit::Kind::RosterSnapshot && !b.header.chunks.is_empty());
        bad_parts += usize::from(b.parts.iter().any(|p| matches!(osis_base::decode(&p.delta, &osis_base::Limits { max_depth: 8, max_bytes: p.delta.len() }), Ok(Value::List(l)) if matches!(l.as_slice(), [Value::Int(1)]))));
    }
    let ids: std::collections::BTreeSet<_> = played.packs.iter().map(|x| x.id).collect();
    let later: Vec<usize> = (0..played.packs.len()).collect();
    for variant in 0..6 {
        let hidden: Vec<usize> = later.iter().copied().filter(|_| variant > 0 && rng.below(5) == 0).collect();
        let sync: Vec<Tid> = played.things.iter().copied().filter(|_| variant % 2 == 1 && rng.below(2) == 0).collect();
        let keep: Vec<usize> = later.iter().copied().filter(|i| !hidden.contains(i)).collect();
        // the blobs of the roster snapshots' linked frontiers stay away, then come
        let away = variant % 3 == 2;
        let away_from = |i: usize| -> Vec<(osis_base::BlobId, Vec<u8>)> {
            let pk = &played.packs[i];
            let h = CommitBlob::decode(&pk.bytes).unwrap().header;
            let frontier: std::collections::BTreeSet<_> = if away && h.kind == osis_commit::Kind::RosterSnapshot { h.chunks.iter().map(|c| c.blob).collect() } else { Default::default() };
            pk.blobs.iter().filter(|(b, _)| !frontier.contains(b)).cloned().collect()
        };
        let held_of = |p: &mut Peer| {
            let roster: Vec<String> = played.things.iter().map(|t| format!("{:?}", p.engine.roster(t))).collect();
            // first and last deaths may date later by order (spec/commits.md §5)
            let seen: Vec<(String, String)> = observe(&mut p.engine, &ids).into_iter().map(|(k, v)| (k, v.split(' ').filter(|w| !w.starts_with("deaths=")).collect::<Vec<_>>().join(" "))).collect();
            // a part pending at its expiry counts as never received: its aspect, flagged, may differ
            // from one that applied it before T (spec/commits.md §5)
            let expired: Vec<String> = p.engine.suspects().unwrap().into_iter().filter(|x| x.3 & osis_node::retention::suspect::Why::PendingExpiry as u8 != 0).map(|(t, a, _, _)| format!("aspect {t} {}", a.as_str())).collect();
            (seen, roster, expired)
        };
        // the state read with the blobs away, and read once they came
        let read = |toks: &[Vec<u8>], blobs: &[usize], toggles: Option<&[(usize, Tid, bool)]>| {
            let mut p = Peer::new(FRESH, played.now).unwrap();
            let mut relay = Relay::default();
            if toggles.is_none() {
                for t in &sync {
                    p.engine.set_syncing(*t, true).unwrap();
                }
            }
            for (at, b) in toks.iter().enumerate() {
                for (w, t, on) in toggles.unwrap_or(&[]) {
                    if *w == at {
                        p.engine.set_syncing(*t, *on).unwrap();
                    }
                }
                relay.give(&mut p, b, away_from(blobs[at]));
            }
            for t in sync.iter() {
                p.engine.set_syncing(*t, true).unwrap();
            }
            relay.settle(&mut p);
            let first = held_of(&mut p);
            for i in blobs {
                p.engine.put_blobs(played.packs[*i].blobs.clone()).unwrap();
            }
            relay.settle(&mut p);
            (first, held_of(&mut p))
        };
        let whole: Vec<Vec<u8>> = keep.iter().map(|i| played.packs[*i].bytes.clone()).collect();
        let (want, want_after) = read(&whole, &keep, None);
        for _ in 0..5 {
            let mut toks: Vec<(usize, Vec<u8>)> = keep.iter().flat_map(|i| cuts(&played, *i).into_iter().map(move |b| (*i, b))).collect();
            // a whole copy again (under a second label), a relay's junk
            for _ in 0..rng.below(4) {
                let i = keep[rng.below(keep.len() as u64) as usize];
                toks.push((i, played.packs[i].bytes.clone()));
            }
            for _ in 0..rng.below(4) {
                let i = keep[rng.below(keep.len() as u64) as usize];
                let j = junk_copy(&played, i, &mut rng);
                toks.push((i, j));
            }
            for i in (1..toks.len()).rev() {
                toks.swap(i, rng.below(i as u64 + 1) as usize);
            }
            let (is, bs): (Vec<usize>, Vec<Vec<u8>>) = toks.into_iter().unzip();
            let (got, got_after) = read(&bs, &is, None);
            for (name, (g, ge), (w, we)) in [("as delivered", (&got.0, &got.2), (&want.0, &want.2)), ("blobs come", (&got_after.0, &got_after.2), (&want_after.0, &want_after.2))] {
                let stands = |x: &&(String, String)| !ge.contains(&x.0) && !we.contains(&x.0);
                let (g, w): (Vec<_>, Vec<_>) = (g.iter().filter(stands).collect(), w.iter().filter(stands).collect());
                if g != w {
                    let first = g.iter().filter(|x| !w.contains(x)).map(|x| format!("got {x:?}")).chain(w.iter().filter(|x| !g.contains(x)).map(|x| format!("want {x:?}"))).collect::<Vec<_>>().join("; ");
                    bad.push(format!("seed {seed} variant {variant} fixed sync, {name}: {}", first.chars().take(300).collect::<String>()));
                }
            }
            for (name, g, w) in [("as delivered", &got.1, &want.1), ("blobs come", &got_after.1, &want_after.1)] {
                if g != w {
                    let first = g.iter().zip(w).find(|(a, b)| a != b).map(|x| format!("{x:?}"));
                    bad.push(format!("seed {seed} variant {variant} fixed sync roster, {name}: {}", first.unwrap_or_default().chars().take(300).collect::<String>()));
                }
            }
            // the sync set arriving during delivery, same in the end
            let toggles: Vec<(usize, Tid, bool)> = sync.iter().map(|t| (rng.below(bs.len() as u64 + 1) as usize, *t, true)).collect();
            let (changing, _) = read(&bs, &is, Some(&toggles));
            if changing.1 != want.1 {
                let first = changing.1.iter().zip(&want.1).find(|(a, b)| a != b).map(|x| format!("{x:?}"));
                bad.push(format!("seed {seed} variant {variant} changing sync, roster: {}", first.unwrap_or_default().chars().take(300).collect::<String>()));
            }
        }
    }
    PartsSeed { played: true, bad_parts, linked, bad }
}

fn parts_replay(s: u64) -> String {
    format!("OSIS_PARTS_START={s} OSIS_PARTS_SEEDS=1 cargo test --workspace --test it parts::parts_differential_large_spec_commits_4 -- --ignored --exact")
}

#[test]
#[ignore]
fn parts_differential_large_spec_commits_4() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_PARTS_START", "OSIS_PARTS_SEEDS", 1..151);
    let n = seeds.range.end - seeds.range.start;
    let all = seeds.run("parts::parts_differential_large_spec_commits_4", parts_replay, parts_seed);
    let played_n = all.iter().filter(|s| s.played).count() as u64;
    // what the histories hold of the hostile cases
    let (bad_parts, linked): (usize, usize) = (all.iter().map(|s| s.bad_parts).sum(), all.iter().map(|s| s.linked).sum());
    let bad: Vec<&String> = all.iter().flat_map(|s| &s.bad).collect();
    eprintln!("{played_n} of {n} histories played, {bad_parts} commits with a bad part, {linked} snapshots linking a frontier");
    assert!(played_n > n / 2);
    assert!(n < 10 || (bad_parts > 0 && linked > 0), "the histories hold the hostile cases");
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.iter().take(12).map(|x| x.as_str()).collect::<Vec<_>>().join("\n"));
}

// spec/commits.md §4, §5: a part past its expiry decides nothing about its commit. X's part arrives past
// T, Y's record is away. With X's record held the part could join, with it away the part goes; either
// way, in every order, the commit waits on Y as if the part never came, and applies when Y's record does
// (`parts_differential` seeds 121019, 934068, 936047, 936059: as made it applied, X's part joined).
#[test]
fn part_past_expiry_decides_nothing_spec_commits_4() {
    use crate::common::*;
    let mut lp = net(2, 67);
    let setup = packages(&mut lp, 0);
    let new_of = |lp: &mut osis_node::local_peer::LocalPeer, known: &[osis_node::local_peer::Package]| -> Vec<osis_node::local_peer::Package> { packages(lp, 0).into_iter().filter(|p| !known.iter().any(|k| k.id == p.id)).collect() };
    let x = new_thing(&mut lp, 0);
    let rec_x = new_of(&mut lp, &setup);
    let known: Vec<_> = setup.iter().chain(&rec_x).cloned().collect();
    let y = new_thing(&mut lp, 0);
    let rec_y = new_of(&mut lp, &known);
    let t = osis_base::WallMs(lp.peers[0].engine.now().0 + 1_000);
    let mut m = Mutation::new();
    m.set(x, &BRIEF, &s("brief")).unwrap();
    m.expires(x, &BRIEF, t).unwrap();
    m.set(y, &REG, &s("stays")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == c).unwrap();
    lp.peers[0].clock.advance(2_000);
    let now = lp.peers[0].engine.now();
    let ids: std::collections::BTreeSet<_> = packages(&mut lp, 0).iter().map(|p| p.id).collect();
    let (whole, on_x, on_y) = (pk.bytes.clone(), on(&pk, x), on(&pk, y));
    let rec = rec_x[0].bytes.clone();
    let orders: Vec<Vec<&[u8]>> = vec![vec![&rec, &whole], vec![&whole, &rec], vec![&on_y, &on_x, &rec], vec![&on_x, &on_y, &rec], vec![&rec, &on_x, &on_y], vec![&rec, &on_y, &on_x], vec![&on_x, &rec, &on_y]];
    for syncs in [vec![], vec![x]] {
        let mut want: Option<Vec<(String, String)>> = None;
        for (n, order) in orders.iter().enumerate() {
            let mut p = Peer::new(FRESH, now).unwrap();
            for t in &syncs {
                p.engine.set_syncing(*t, true).unwrap();
            }
            for pk in &setup {
                let _ = p.engine.ingest(&pk.bytes, Vec::new());
            }
            for b in order {
                let _ = p.engine.ingest(b, Vec::new());
            }
            p.engine.reexamine().unwrap();
            assert!(!p.engine.commit_ids().contains(&c), "syncs {}, order {n}: applied on the expired part", syncs.len());
            assert_eq!(p.engine.pending(), vec![(c, Reason::UnknownCreated(y))], "syncs {}, order {n}", syncs.len());
            assert!(p.engine.suspects().unwrap().iter().any(|f| f.0 == x && f.1 == ak("t:brief.0")), "syncs {}, order {n}: the part went, flagged", syncs.len());
            for pk in &rec_y {
                let _ = p.engine.ingest(&pk.bytes, Vec::new());
            }
            p.engine.reexamine().unwrap();
            assert!(p.engine.commit_ids().contains(&c) && p.engine.pending().is_empty(), "syncs {}, order {n}: {:?}", syncs.len(), p.engine.pending());
            assert_eq!(p.engine.get(&y, &ak("t:reg.0")).unwrap(), Some(s("stays")));
            assert_eq!(p.engine.get(&x, &ak("t:brief.0")).unwrap(), None);
            let got = observe(&mut p.engine, &ids);
            let w = want.get_or_insert_with(|| got.clone());
            let first = got.iter().zip(w.iter()).find(|(a, b)| a != b);
            assert!(got == *w, "syncs {}, order {n}: {first:?}", syncs.len());
        }
    }
}

// spec/commits.md §4: a relay's junk part on a thing whose record is away cannot be hash-checked; it
// keeps out no true part, which is taken when the record comes.
#[test]
fn junk_part_keeps_out_no_true_part_spec_commits_4() {
    use Step::*;
    let played = play(SEED, &[New { by: 0, parent: 0, write: true }, Advance { who: None, ms: 1000 }, Two { by: 0, a: 0, b: 1, v: 7 }]);
    let (rec, last, h) = (played.base, played.packs.len() - 1, played.things[1]);
    let good = part(&played, last, Some(h));
    let mut junk = CommitBlob::decode(&good).unwrap();
    let other = CommitBlob::decode(&played.packs[last].bytes).unwrap();
    let swap = other.parts.iter().find(|x| !junk.parts.iter().any(|y| y.delta == x.delta)).unwrap().delta.clone();
    for p in &mut junk.parts {
        p.delta = swap.clone();
    }
    let mut p = Peer::new(FRESH, played.now).unwrap();
    for pk in &played.packs[..rec] {
        p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    let mut relay = Relay::default();
    relay.give(&mut p, &junk.encode(), Vec::new());
    relay.give(&mut p, &good, Vec::new());
    relay.give(&mut p, &played.packs[rec].bytes, played.packs[rec].blobs.clone());
    assert_eq!(p.engine.get(&h, &reg()).unwrap(), v("v7"));
}

// spec/commits.md §4 (`examine`'s invariant): a commit on two synced things, the H part expired
// (counts as held) with its pages away. It holds nothing back, in either order: a missing one would
// not.
#[test]
fn counted_as_held_part_order_spec_commits_4() {
    use crate::common::*;
    let map: std::collections::BTreeMap<Value, Value> = (0..2000).map(|i| (Value::Str(format!("key {i:05}")), Value::Str("v".repeat(60)))).collect();
    let big = Value::Map(map);
    let mut read = Vec::new();
    for first_g in [true, false] {
        let (mut lp, g, h, pk) = two_things(61, |m, g, h| {
            m.set(g, &REG, &s("small")).unwrap();
            m.set(h, &BIG, &big).unwrap();
            m.expires(h, &BIG, osis_base::WallMs(1_700_000_001_000)).unwrap();
        });
        assert!(!pk.blobs.is_empty(), "paged");
        lp.peers[1].clock.advance(10_000_000);
        let e = &mut lp.peers[1].engine;
        e.set_syncing(g, true).unwrap();
        e.set_syncing(h, true).unwrap();
        for t in if first_g { [g, h] } else { [h, g] } {
            let _ = e.ingest(&on(&pk, t), Vec::new());
        }
        e.reexamine().unwrap();
        read.push(e.get(&g, &ak("t:reg.0")).unwrap());
    }
    assert_eq!(read[0], read[1]);
}

/// Every shape of pack `i`'s delivery: one blob; split by aspect, in every order; again whole after
/// its parts, under a second label; each part twice.
fn shapes(played: &Played, i: usize) -> Vec<Vec<Vec<u8>>> {
    let whole = played.packs[i].bytes.clone();
    let cut = cuts(played, i);
    let mut out = vec![vec![whole.clone()], vec![whole.clone(), whole.clone()]];
    for perm in permutations(cut.len()) {
        let order: Vec<Vec<u8>> = perm.iter().map(|x| cut[*x].clone()).collect();
        let mut again = order.clone();
        again.push(whole.clone());
        let twice: Vec<Vec<u8>> = order.iter().flat_map(|b| [b.clone(), b.clone()]).collect();
        out.extend([order, again, twice]);
    }
    out
}

// spec/commits.md §4: a part that hashes right and is bad by itself, beside good ones, on content, a
// role commit and a roster snapshot, synced or not: in every shape of delivery the node reads alike,
// and the good parts stand wherever a synced thing does not hold them back: a bad part answers its
// delta's wait (no copy can differ from it, so no later true copy exists to wait for).
#[test]
fn bad_part_every_shape_reads_alike_spec_commits_4() {
    use Step::*;
    for how in 0..4u8 {
        let tick = || Advance { who: None, ms: 1000 };
        let played = play(SEED, &[NewTop { by: 0 }, NewTop { by: 0 }, tick(), BadPart { by: 0, a: 1, b: 2, how }]);
        let last = played.packs.len() - 1;
        let (a, b) = (played.things[1], played.things[2]);
        let parts = CommitBlob::decode(&played.packs[last].bytes).unwrap().parts.len();
        assert!(parts >= 2, "how {how}: a bad part beside a good one");
        let ids: std::collections::BTreeSet<_> = played.packs.iter().map(|x| x.id).collect();
        for syncs in [vec![], vec![a], vec![b], vec![a, b]] {
            let mut want = None;
            for shape in shapes(&played, last) {
                let mut p = Peer::new(FRESH, played.now).unwrap();
                for t in &syncs {
                    p.engine.set_syncing(*t, true).unwrap();
                }
                for pk in &played.packs[..last] {
                    p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
                }
                for x in &shape {
                    let _ = p.engine.ingest(x, Vec::new());
                }
                p.engine.reexamine().unwrap();
                let roster: Vec<String> = played.things.iter().map(|t| format!("{:?}", p.engine.roster(t))).collect();
                let got = (observe(&mut p.engine, &ids), roster, p.engine.pending());
                assert!(got.2.is_empty(), "how {how}: nothing waits for a part held bad: {:?}", got.2);
                if how == 0 {
                    assert_eq!(p.engine.get(&a, &reg()).unwrap(), v("beside bad"), "how {how}, syncs {}", syncs.len());
                    assert_eq!(p.engine.get(&b, &reg()).unwrap(), v("top"), "the bad part never applies");
                }
                let w = want.get_or_insert_with(|| got.clone());
                assert!(got == *w, "how {how}, syncs {}: {:?}", syncs.len(), got.0.iter().zip(w.0.iter()).find(|(a, b)| a != b));
            }
        }
    }
}

/// `played`'s last pack (two things, the second's record pack `rec` away) and its part on the record's
/// thing with junk deltas, or another's signature.
fn relay_case() -> (Played, usize, usize, Tid, Vec<u8>) {
    use Step::*;
    let played = play(SEED, &[New { by: 0, parent: 0, write: true }, Advance { who: None, ms: 1000 }, Two { by: 0, a: 0, b: 1, v: 7 }]);
    let (rec, last, h) = (played.base, played.packs.len() - 1, played.things[1]);
    let good = part(&played, last, Some(h));
    (played, rec, last, h, good)
}

fn with_delta(blob: &[u8], fill: u8, len: usize) -> Vec<u8> {
    let mut b = CommitBlob::decode(blob).unwrap();
    for p in &mut b.parts {
        p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![fill; len])]));
    }
    b.encode()
}

// spec/commits.md §4 (copies): what a relay sends never keeps out what the author signed: junk under the
// same ID, before or after the true part, a junk signature with its author away, on a thing synced or
// not, two junk copies, all junk: the true one applies when the record comes.
#[test]
fn relay_copies_keep_out_nothing_spec_commits_4() {
    let (played, rec, last, h, good) = relay_case();
    let junk1 = with_delta(&good, 1, 40);
    let junk2 = with_delta(&good, 2, 40);
    let cases: [Vec<&Vec<u8>>; 5] = [vec![&junk1, &good], vec![&good, &junk1], vec![&junk1, &junk2, &good], vec![&junk1, &good, &junk2], vec![&junk1, &junk1, &good, &good]];
    for syncs in [vec![], vec![h]] {
        for (n, order) in cases.iter().enumerate() {
            let mut p = Peer::new(FRESH, played.now).unwrap();
            let mut relay = Relay::default();
            for t in &syncs {
                p.engine.set_syncing(*t, true).unwrap();
            }
            for pk in &played.packs[..rec] {
                p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
            }
            for b in order {
                relay.give(&mut p, b, Vec::new());
            }
            relay.give(&mut p, &played.packs[rec].bytes, played.packs[rec].blobs.clone());
            relay.give(&mut p, &part(&played, last, Some(played.things[0])), Vec::new());
            assert_eq!(p.engine.get(&h, &reg()).unwrap(), v("v7"), "case {n}, syncs {}", syncs.len());
            assert!(p.engine.pending().is_empty(), "case {n}");
            assert!(relay.again <= order.len(), "case {n}: each copy once: {}", relay.again);
        }
    }
    // a slot the header does not list is not kept, its author away: a sender cannot grow the pending
    // blob by them
    let mut p = Peer::new(FRESH, played.now).unwrap();
    let _ = p.engine.ingest(&good, Vec::new());
    let mut stray = CommitBlob::decode(&good).unwrap();
    stray.parts[0].ai = 50_000;
    let _ = p.engine.ingest(&stray.encode(), Vec::new());
    assert_eq!(CommitBlob::decode(&p.engine.commit_bytes(&played.packs[last].id).unwrap().unwrap()).unwrap().parts.len(), 1);
    // junk in the slot of a `created.0` part, the author's own: the true copy proves itself, or nothing
    // could tell; and its signature, the first copy's being junk, is then checked and taken
    let carrier = played.packs.iter().find(|pk| CommitBlob::decode(&pk.bytes).unwrap().parts.iter().any(|x| CommitBlob::decode(&pk.bytes).unwrap().header.aspects[x.ai].ak.as_str() == "created.0")).unwrap();
    for junk_sig in [false, true] {
        let mut p = Peer::new(FRESH, played.now).unwrap();
        let mut relay = Relay::default();
        let mut first = CommitBlob::decode(&with_delta(&carrier.bytes, 4, 40)).unwrap();
        if junk_sig {
            first.signature = osis_crypto::Signature::from_slice(&[9; 64]).unwrap();
        }
        relay.give(&mut p, &first.encode(), Vec::new());
        assert!(!p.engine.commit_ids().contains(&carrier.id));
        relay.give(&mut p, &carrier.bytes, carrier.blobs.clone());
        assert!(p.engine.commit_ids().contains(&carrier.id), "junk signature {junk_sig}");
    }
    // a copy is judged by what can be checked, whichever slot comes first
    let mut p = Peer::new(FRESH, played.now).unwrap();
    for pk in &played.packs[..rec] {
        p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    let whole = CommitBlob::decode(&played.packs[last].bytes).unwrap();
    assert_eq!(p.engine.parts_genuine(&whole), None, "H's part cannot be checked");
    let g = played.things[0];
    let mut bad_g = whole.clone();
    let at = bad_g.parts.iter().position(|x| whole.header.aspects[x.ai].tid == g).unwrap();
    bad_g.parts[at].delta = osis_base::encode(&Value::List(vec![Value::Int(5)]));
    assert_eq!(p.engine.parts_genuine(&bad_g), Some(false), "G's part can");
    // all junk: the commit waits for nothing that came; a true copy is taken later
    let mut p = Peer::new(FRESH, played.now).unwrap();
    let mut relay = Relay::default();
    for pk in &played.packs[..rec] {
        p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    relay.give(&mut p, &junk1, Vec::new());
    relay.give(&mut p, &junk2, Vec::new());
    relay.give(&mut p, &played.packs[rec].bytes, played.packs[rec].blobs.clone());
    assert_ne!(p.engine.get(&h, &reg()).unwrap(), v("v7"));
    assert!(p.engine.pending().is_empty(), "nothing true of it here");
    relay.give(&mut p, &good, Vec::new());
    assert_eq!(p.engine.get(&h, &reg()).unwrap(), v("v7"));
    // the signature: its author's record away, so nothing checks it yet
    let (played, _, last, _, _) = relay_case();
    let other = CommitBlob::decode(&played.packs[last - 1].bytes).unwrap();
    let mut forged = CommitBlob::decode(&played.packs[last].bytes).unwrap();
    forged.signature = other.signature;
    let forged = forged.encode();
    for first in [&forged, &played.packs[last].bytes] {
        let second = if std::ptr::eq(first, &forged) { &played.packs[last].bytes } else { &forged };
        let mut p = Peer::new(FRESH, played.now).unwrap();
        let mut relay = Relay::default();
        relay.give(&mut p, first, Vec::new());
        relay.give(&mut p, second, Vec::new());
        assert!(!p.engine.commit_ids().contains(&played.packs[last].id));
        for pk in &played.packs[..last] {
            relay.give(&mut p, &pk.bytes, pk.blobs.clone());
        }
        assert!(p.engine.commit_ids().contains(&played.packs[last].id), "the true signature taken");
        assert_eq!(p.engine.get(&played.things[1], &reg()).unwrap(), v("v7"));
    }
    // only junk signatures: the commit goes when its author comes, and a true copy is taken after
    let mut p = Peer::new(FRESH, played.now).unwrap();
    let mut relay = Relay::default();
    relay.give(&mut p, &forged, Vec::new());
    for pk in &played.packs[..last] {
        relay.give(&mut p, &pk.bytes, pk.blobs.clone());
    }
    assert!(!p.engine.commit_ids().contains(&played.packs[last].id));
    assert!(p.engine.pending().is_empty());
    assert!(matches!(p.engine.ingest(&played.packs[last].bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
}

// spec/requirements.md (no unbounded work from peer input): a flood however large keeps out nothing, and
// costs one look per copy: a pending blob holds one copy of a slot, and each junk copy is judged once.
#[test]
fn flood_of_copies_keeps_out_nothing_spec_commits_4() {
    const COPIES: usize = 300;
    let (played, rec, _, h, good) = relay_case();
    for at in [0, COPIES / 2, COPIES] {
        let mut p = Peer::new(FRESH, played.now).unwrap();
        let mut relay = Relay::default();
        for pk in &played.packs[..rec] {
            p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        for i in 0..=COPIES {
            if i == at {
                relay.give(&mut p, &good, Vec::new());
            }
            if i < COPIES {
                relay.give(&mut p, &with_delta(&good, 7, 40 + i), Vec::new());
            }
        }
        relay.give(&mut p, &played.packs[rec].bytes, played.packs[rec].blobs.clone());
        relay.give(&mut p, &part(&played, played.packs.len() - 1, Some(played.things[0])), Vec::new());
        assert_eq!(p.engine.get(&h, &reg()).unwrap(), v("v7"), "true copy at {at}");
        assert!(relay.again <= 1, "only the true copy again, not the flood: {}", relay.again);
        assert!(p.engine.take_redeliver().is_empty());
    }
}

// spec/commits.md §4: a part of a role commit that does not hash holds no delta: the commit is not
// held as any part of it is, and waits whole on a synced thing with nothing applied.
#[test]
fn role_commit_of_junk_holds_nothing_spec_commits_4() {
    let hs = histories();
    let role = &hs[1].played;
    let last = role.packs.len() - 1;
    let id = role.packs[last].id;
    let g = role.things[0];
    let junk = with_delta(&role.packs[last].bytes, 9, 40);
    let mut p = Peer::new(FRESH, role.now).unwrap();
    p.engine.set_syncing(g, true).unwrap();
    for pk in &role.packs[..last] {
        p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    let _ = p.engine.ingest(&junk, Vec::new());
    p.engine.reexamine().unwrap();
    assert!(!p.engine.commit_ids().contains(&id), "junk is no part of it");
    p.engine.ingest(&role.packs[last].bytes, Vec::new()).unwrap();
    assert!(p.engine.commit_ids().contains(&id));
}

// spec/commits.md §2, §4: a delta on an aspect of the wrong storage class is never applied, by anyone,
// so a node syncing the thing does not wait for it: the rest applies whether the part came or not.
#[test]
fn wrong_class_delta_is_not_waited_for_spec_commits_4() {
    use crate::common::*;
    let (mut lp, g, _, _) = two_things(67, |m, g, _| { m.set(g, &REG, &s("first")).unwrap(); });
    let key = ak("t:tags.0~");
    let mut m = Mutation::new();
    m.set(g, &REG, &s("kept")).unwrap();
    m.op(g, &key, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("durable")) }).unwrap();
    let id = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    assert_eq!(CommitBlob::decode(&pk.bytes).unwrap().parts.len(), 1, "its author's copy holds no such part");
    let e = &mut lp.peers[1].engine;
    e.set_syncing(g, true).unwrap();
    assert!(matches!(e.ingest(&pk.bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(e.get(&g, &ak("t:reg.0")).unwrap(), Some(s("kept")));
    // a copy holding one, while the commit waits, names nothing: such a part has no true copy to look for
    let mut lp = net(2, 69);
    let known = packages(&mut lp, 0);
    let h = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(h, &REG, &s("kept")).unwrap();
    m.op(h, &key, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("durable")) }).unwrap();
    let (id, bytes) = lp.peers[0].engine.commit_forged(m, [(Tid::from_bytes([0; 15]), key.clone())].into()).unwrap().unwrap();
    let p = &mut lp.peers[1];
    for pk0 in &known {
        p.engine.ingest(&pk0.bytes, pk0.blobs.clone()).unwrap();
    }
    let mut relay = Relay::default();
    relay.give(p, &bytes, Vec::new());
    relay.give(p, &bytes, Vec::new());
    assert!(!p.engine.commit_ids().contains(&id));
    assert_eq!(relay.again, 0);
}

// spec/commits.md §4: copies of a part whose aspect list goes by link settle like any: junk first, its
// thing's record away, the header resolved from the commit's blobs.
#[test]
fn copies_of_a_linked_aspect_list_settle_spec_commits_4() {
    use crate::common::*;
    let mut lp = net(2, 68);
    let g = new_thing(&mut lp, 0);
    let known = packages(&mut lp, 0);
    let h = new_thing(&mut lp, 0);
    let made = packages(&mut lp, 0);
    let record: Vec<_> = made.into_iter().filter(|p| !known.iter().any(|x| x.id == p.id)).collect();
    lp.peers[0].clock.advance(10);
    let mut m = Mutation::new();
    let name = |i: usize| osis_base::Ak::new(format!("u:{}{i:05}.0", "a".repeat(100))).unwrap();
    let first = name(0);
    for i in 0..800 {
        m.set(h, &name(i), &s("v")).unwrap();
    }
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    assert!(lp.peers[0].engine.header(&id).unwrap().links.aspects.is_some(), "the aspect list goes by link");
    let junk = with_delta(&pk.bytes, 3, 40);
    for pk0 in &known {
        lp.deliver(1, pk0).unwrap();
    }
    let p = &mut lp.peers[1];
    let mut relay = Relay::default();
    relay.give(p, &junk, pk.blobs.clone());
    relay.give(p, &pk.bytes, pk.blobs.clone());
    assert!(!p.engine.commit_ids().contains(&id) && !p.engine.pending().is_empty());
    let _ = g;
    for x in &record {
        relay.give(p, &x.bytes, x.blobs.clone());
    }
    let e = &mut p.engine;
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert_eq!(e.get(&h, &first).unwrap(), Some(s("v")));
}

// Reviewer's differential (spec/permissions.md §6, spec/commits.md §4): a role's standing does not
// read what a node syncs: one held set, with linked frontiers away and after they come, reads one
// roster under every sync set, in random shapes and orders, a restart among them.
fn rosters_alike(seeds: impl Iterator<Item = u64>) {
    let mut bad = Vec::new();
    let mut linked = 0;
    for seed in seeds {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let steps = diff_steps(&mut rng);
        let Ok(played) = std::panic::catch_unwind(|| play(seed, &steps)) else { continue };
        let frontier_of = |i: usize| -> std::collections::BTreeSet<osis_base::BlobId> {
            let h = CommitBlob::decode(&played.packs[i].bytes).unwrap().header;
            if h.kind == osis_commit::Kind::RosterSnapshot { h.chunks.iter().map(|c| c.blob).collect() } else { Default::default() }
        };
        linked += (0..played.packs.len()).filter(|i| !frontier_of(*i).is_empty()).count();
        let rosters = |p: &mut Peer| -> Vec<String> { played.things.iter().map(|t| format!("{:?}", p.engine.roster(t))).collect() };
        let all: Vec<usize> = (0..played.packs.len()).collect();
        let read = |sync: &[Tid], rng: &mut Rng, cut: bool, restart: bool, all: &[usize]| {
            let mut p = Peer::new(FRESH, played.now).unwrap();
            for t in sync {
                p.engine.set_syncing(*t, true).unwrap();
            }
            let mut toks: Vec<(usize, Vec<u8>)> = all.iter().flat_map(|i| if cut { cuts(&played, *i) } else { vec![played.packs[*i].bytes.clone()] }.into_iter().map(move |b| (*i, b))).collect();
            for i in (1..toks.len()).rev() {
                toks.swap(i, rng.below(i as u64 + 1) as usize);
            }
            for (i, b) in &toks {
                let away = frontier_of(*i);
                let _ = p.engine.ingest(b, played.packs[*i].blobs.iter().filter(|(x, _)| !away.contains(x)).cloned().collect());
            }
            p.engine.reexamine().unwrap();
            if restart {
                p.restart(seed).unwrap();
                p.engine.reexamine().unwrap();
            }
            let first = rosters(&mut p);
            for i in all {
                p.engine.put_blobs(played.packs[*i].blobs.clone()).unwrap();
            }
            p.engine.reexamine().unwrap();
            (first, rosters(&mut p))
        };
        for round in 0..3 {
            // some packs stay away, alike in each
            let keep: Vec<usize> = all.iter().copied().filter(|_| round == 0 || rng.below(5) != 0).collect();
            let want = read(&[], &mut rng, false, false, &keep);
            for variant in 0..6 {
                let sync: Vec<Tid> = match variant {
                    0 | 1 => played.things.clone(),
                    _ => played.things.iter().copied().filter(|_| rng.below(2) == 0).collect(),
                };
                let got = read(&sync, &mut rng, variant % 2 == 1, variant >= 4, &keep);
                for (name, g, w) in [("away", &got.0, &want.0), ("come", &got.1, &want.1)] {
                    if g != w {
                        let first = g.iter().zip(w).find(|(a, b)| a != b).map(|x| format!("{x:?}")).unwrap_or_default();
                        bad.push(format!("seed {seed} round {round} variant {variant} hidden {:?} sync {sync:?} blobs {name}: {}", all.iter().filter(|i| !keep.contains(i)).collect::<Vec<_>>(), first.chars().take(300).collect::<String>()));
                    }
                }
            }
        }
    }
    assert!(linked > 0);
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.iter().take(12).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
#[ignore]
fn rosters_alike_across_sync_sets_large_spec_permissions_6() {
    let (from, n) = (std::env::var("OSIS_ROSTERS_START").ok().and_then(|x| x.parse().ok()).unwrap_or(1u64), std::env::var("OSIS_ROSTERS_SEEDS").ok().and_then(|x| x.parse().ok()).unwrap_or(60u64));
    rosters_alike(from..from + n);
}

// The histories that found it: a removal names an entry of a snapshot whose frontier is away. Unsynced
// the snapshot's roster part applied and its entries are known, so one wait holding it whole on a
// synced thing left the holder an admin there and removed elsewhere.
#[test]
fn removal_of_a_withheld_entry_alike_across_sync_sets_spec_permissions_6() {
    rosters_alike([63044, 63055].into_iter());
}

// spec/commits.md §4: a bad part on a synced thing answers its wait with the commit's other part
// waiting alone: applied whichever came first or came together.
#[test]
fn bad_part_answers_beside_a_waiting_part_spec_commits_4() {
    use Step::*;
    let played = play(SEED, &[New { by: 0, parent: 0, write: true }, New { by: 0, parent: 0, write: true }, Advance { who: None, ms: 1000 }, BadPart { by: 0, a: 1, b: 2, how: 0 }]);
    let (hidden, last) = (played.base, played.packs.len() - 1);
    let (a, b) = (played.things[1], played.things[2]);
    let ids: std::collections::BTreeSet<_> = played.packs.iter().map(|x| x.id).collect();
    let read = |order: &[Vec<u8>]| {
        let mut p = Peer::new(FRESH, played.now).unwrap();
        p.engine.set_syncing(b, true).unwrap();
        for (_, pk) in played.packs.iter().enumerate().filter(|(i, _)| *i != hidden && *i != last) {
            let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        for t in order {
            let _ = p.engine.ingest(t, Vec::new());
        }
        p.engine.reexamine().unwrap();
        (observe(&mut p.engine, &ids), p.engine.commit_ids().contains(&played.packs[last].id))
    };
    let (whole, on_a, on_b) = (played.packs[last].bytes.clone(), part(&played, last, Some(a)), part(&played, last, Some(b)));
    let want = read(std::slice::from_ref(&whole));
    assert!(want.1, "applied without its bad part, its other part waiting");
    assert_eq!(read(&[on_a.clone(), on_b.clone()]), want);
    assert_eq!(read(&[on_b, on_a]), want);
}

// spec/commits.md §4 (copies): a true `created.0` proves itself under a header whose aspect list goes by
// link too: the stored copy's header reads empty until its list is resolved.
#[test]
fn true_record_replaces_junk_under_a_linked_header_spec_commits_4() {
    use crate::common::*;
    let mut lp = net(2, 71);
    let known = packages(&mut lp, 0);
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, e.identity().tid());
    for i in 0..800 {
        m.set(t, &ak(&format!("u:{}{i:05}.0", "a".repeat(100))), &s("v")).unwrap();
    }
    let id = e.commit(m).unwrap().unwrap();
    assert!(e.header(&id).unwrap().links.aspects.is_some(), "the aspect list goes by link");
    let pk = e.package(&id).unwrap().unwrap();
    let whole = CommitBlob::decode(&pk.bytes).unwrap();
    let mut resolved = whole.clone();
    resolved.header = (*e.header(&id).unwrap()).clone();
    let created = resolved.parts.iter().position(|p| resolved.header.aspects[p.ai].ak.as_str() == "created.0").unwrap();
    let mut junk = whole.clone();
    junk.parts = vec![junk.parts[created].clone()];
    junk.parts[0].delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![9; 40])]));
    let p = &mut lp.peers[1];
    for k in &known {
        p.engine.ingest(&k.bytes, k.blobs.clone()).unwrap();
    }
    p.engine.ingest(&junk.encode(), pk.blobs.clone()).unwrap();
    assert!(!p.engine.commit_ids().contains(&id));
    p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    p.engine.reexamine().unwrap();
    assert!(p.engine.commit_ids().contains(&id), "{:?}", p.engine.pending());
}

/// Three things of peer 0's and the commits making them.
struct Forge {
    lp: osis_node::local_peer::LocalPeer,
    setup: Vec<osis_node::local_peer::Package>,
    x: Tid,
    y: Tid,
    z: Tid,
}

fn forge_setup(seed: u64) -> Forge {
    use crate::common::*;
    let mut lp = net(2, seed);
    let (x, y, z) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let setup = packages(&mut lp, 0);
    Forge { lp, setup, x, y, z }
}

#[derive(Clone, Copy, PartialEq)]
enum Made {
    Good,
    /// Hashes, bad by itself.
    Bad,
    /// A later build's: parks here.
    Parked,
}

/// Peer 0's signed commit of `parts` (thing, key, what, expiry in ms from now), as no writer here makes it.
fn forge(f: &mut Forge, parts: &[(Tid, &str, Made, Option<u64>)]) -> CommitBlob {
    use crate::common::*;
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Writer, create, encode_delta};
    f.lp.peers[0].clock.advance(10);
    let e = &mut f.lp.peers[0].engine;
    let recs = [f.x, f.y, f.z].iter().map(|t| e.get_typed(t, &osis_schema::core_types::CREATED).unwrap().unwrap()).collect();
    let author = e.tid();
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    let form = crate::common::forged_session(author);
    let own = form.own_source(author, osis_base::CommitId([0; 32]));
    let now = e.now().0;
    let mut cb = CommitBuilder::new(Kind::Content, ts, author, author, form);
    for (n, (t, k, how, exp)) in parts.iter().enumerate() {
        let mut w = Writer::new(ts, own.clone(), 1000 + n as u64 * 100);
        let c = create(&mut w, &osis_crdt::AnyView, &s("ok")).unwrap();
        let r = w.range();
        let cx = writer_ctx(form, Kind::Content, ts, author, r.lo, r.hi);
        let d = match how {
            Made::Good => encode_delta(&Delta { nonce: [7; 16], fragment: c }, &cx, None).unwrap(),
            Made::Bad => osis_base::encode(&Value::List(vec![Value::Int(1)])),
            Made::Parked => osis_base::encode(&Value::List(vec![Value::Bytes(vec![0; 16]), Value::List(vec![]), Value::List(vec![]), Value::List(vec![Value::Int(99)])])),
        };
        let mut a = AspectWrite::new(*t, ak(k), r.lo, r.hi, d);
        a.expires = exp.map(|x| now + x);
        cb.aspects.push(a);
    }
    cb.build(&e.identity().keys().signing, &crate::receive::Dedup(recs), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(1)).unwrap().commit
}

/// The parts of `b` on `things`.
fn cut(b: &CommitBlob, things: &[Tid]) -> Vec<u8> {
    let mut x = b.clone();
    let h = x.header.clone();
    x.parts.retain(|p| things.contains(&h.aspects[p.ai].tid));
    x.encode()
}

// spec/commits.md §4: a part past its expiry decides nothing, and a bad part still answers its delta's
// wait beside one: whole or split, in either order, the commit applies with the bad part on a thing the
// node syncs, and waits for it on one it does not.
#[test]
fn bad_part_beside_a_part_past_expiry_spec_commits_4() {
    use crate::common::*;
    for synced in [true, false] {
        let mut f = forge_setup(81);
        let (x, y) = (f.x, f.y);
        let b = forge(&mut f, &[(x, "t:brief.0", Made::Good, Some(1000)), (y, "t:reg.0", Made::Bad, None)]);
        let now = osis_base::WallMs(f.lp.peers[0].engine.now().0 + 5000);
        for order in [vec![b.encode()], vec![cut(&b, &[x]), cut(&b, &[y])], vec![cut(&b, &[y]), cut(&b, &[x])]] {
            let mut p = Peer::new(FRESH, now).unwrap();
            if synced {
                p.engine.set_syncing(y, true).unwrap();
            }
            for pk in &f.setup {
                let _ = p.engine.ingest(&pk.bytes, Vec::new());
            }
            for o in &order {
                let _ = p.engine.ingest(o, Vec::new());
            }
            p.engine.reexamine().unwrap();
            assert_eq!(p.engine.commit_ids().contains(&b.id()), synced, "synced {synced}, {} deliveries", order.len());
            assert_eq!(p.engine.pending().is_empty(), synced, "synced {synced}, {} deliveries", order.len());
            assert_eq!(p.engine.get(&x, &ak("t:brief.0")).unwrap(), None);
        }
    }
}

// spec/versioning.md §2, spec/commits.md §5: a part this build cannot read goes at its expiry like any
// other pending part, whatever its copy waits as: T passing under a parked copy, then what the node syncs
// changing (it recursed for ever, its copy merged back each time). The rest goes on waiting.
#[test]
fn parked_part_goes_at_its_expiry_spec_commits_5() {
    let mut f = forge_setup(82);
    let (x, y, z) = (f.x, f.y, f.z);
    let b = forge(&mut f, &[(x, "t:future.0", Made::Parked, Some(1000)), (y, "t:reg.0", Made::Good, Some(1000)), (z, "t:reg.0", Made::Good, None)]);
    let live = f.lp.peers[0].engine.now();
    let late = osis_base::WallMs(live.0 + 5000);
    let copy_held = |p: &mut Peer| p.engine.commit_bytes(&b.id()).unwrap().is_some_and(|c| !CommitBlob::decode(&c).unwrap().parts.is_empty());
    let new = |now, syncs: &[Tid]| {
        let mut p = Peer::new(FRESH, now).unwrap();
        for t in syncs {
            p.engine.set_syncing(*t, true).unwrap();
        }
        for pk in &f.setup {
            let _ = p.engine.ingest(&pk.bytes, Vec::new());
        }
        p
    };
    // past T when it came: gone at once, flagged
    let mut p = new(late, &[]);
    let _ = p.engine.ingest(&cut(&b, &[x]), Vec::new());
    assert!(!copy_held(&mut p), "no copy past T");
    assert!(p.engine.suspects().unwrap().iter().any(|f| f.0 == x), "flagged");
    p.engine.set_syncing(z, true).unwrap();
    assert_eq!(p.engine.pending(), vec![(b.id(), Reason::WaitDeltas)]);
    // parked alone before T, past it the sync set changes
    let mut p = new(live, &[]);
    assert!(matches!(p.engine.ingest(&cut(&b, &[x]), Vec::new()), Ok(Ingested::Parked(_))));
    assert!(copy_held(&mut p));
    p.clock.advance(5000);
    p.engine.set_syncing(z, true).unwrap();
    assert!(!copy_held(&mut p), "no copy past T");
    assert_eq!(p.engine.pending(), vec![(b.id(), Reason::WaitDeltas)]);
    // parked whole before T, by its synced thing; its timer takes it
    let mut p = new(live, &[x]);
    assert!(matches!(p.engine.ingest(&cut(&b, &[x, y]), Vec::new()), Ok(Ingested::Parked(_))));
    assert!(copy_held(&mut p));
    p.clock.advance(5000);
    p.engine.tick().unwrap();
    assert!(!copy_held(&mut p), "no copy past T");
    assert_eq!(p.engine.pending(), vec![(b.id(), Reason::WaitDeltas)]);
    // the same with the clock alone, no tick: judged at the next look
    let mut p = new(live, &[x]);
    let _ = p.engine.ingest(&cut(&b, &[x, y]), Vec::new());
    p.clock.advance(5000);
    p.engine.reexamine().unwrap();
    assert!(!copy_held(&mut p), "no copy past T");
    assert_eq!(p.engine.pending(), vec![(b.id(), Reason::WaitDeltas)]);
}

// spec/commits.md §4, §5, spec/sync.md §7: an honest commit overwriting a value with a short expiry on X
// beside a write on Y, a stale copy of X's part reaching a node that syncs only X past T. It reads as if
// the part never came: the older value stands, the aspect is flagged and the commit waits for Y. A writer's
// snapshot listing it repairs the aspect (the flag stays: never dormant); or Y's part applies the commit, and another
// copy of X's part joins value-less, as it would have joined had Y's part come first.
#[test]
fn stale_copy_beside_a_thing_not_synced_reads_as_never_received_spec_commits_5() {
    use crate::common::*;
    let mut lp = net(2, 80);
    let (x, y) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let mut m = Mutation::new();
    m.set(x, &BRIEF, &s("older")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let setup = packages(&mut lp, 0);
    let t = osis_base::WallMs(lp.peers[0].engine.now().0 + 1_000);
    let mut m = Mutation::new();
    m.set(x, &BRIEF, &s("short")).unwrap();
    m.expires(x, &BRIEF, t).unwrap();
    m.set(y, &REG, &s("elsewhere")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == c).unwrap();
    lp.peers[0].clock.advance(2_000);
    let now = lp.peers[0].engine.now();
    let brief = ak("t:brief.0");
    let new = || {
        let mut p = Peer::new(FRESH, now).unwrap();
        p.engine.set_syncing(x, true).unwrap();
        for pk in &setup {
            let _ = p.engine.ingest(&pk.bytes, Vec::new());
        }
        p
    };
    let flagged = |p: &mut Peer| p.engine.suspects().unwrap().iter().any(|f| f.0 == x && f.1 == brief);
    let mut p = new();
    let _ = p.engine.ingest(&on(&pk, x), Vec::new());
    assert!(!p.engine.commit_ids().contains(&c));
    assert_eq!(p.engine.pending(), vec![(c, Reason::WaitDeltas)]);
    assert_eq!(p.engine.get(&x, &brief).unwrap(), Some(s("older")));
    assert!(flagged(&mut p));
    // another copy changes nothing while the commit waits
    let _ = p.engine.ingest(&on(&pk, x), Vec::new());
    assert_eq!(p.engine.pending(), vec![(c, Reason::WaitDeltas)]);
    assert_eq!(p.engine.get(&x, &brief).unwrap(), Some(s("older")));
    // a writer's snapshot: its value-less copy supersedes the older value; the flag stays, the
    // digests agree
    let mut r = new();
    let _ = r.engine.ingest(&on(&pk, x), Vec::new());
    lp.peers[0].clock.advance(1);
    let snap = lp.peers[0].engine.snapshot(&x, &brief).unwrap().expect("a snapshot");
    let snap = packages(&mut lp, 0).into_iter().find(|p| p.id == snap).unwrap();
    let _ = r.engine.ingest(&snap.bytes, snap.blobs.clone());
    r.engine.reexamine().unwrap();
    assert_eq!(r.engine.get(&x, &brief).unwrap(), None, "repaired");
    assert!(flagged(&mut r), "a pending-expiry flag is never dormant");
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(r.engine.state_digest(&x, &brief).unwrap(), lp.peers[0].engine.state_digest(&x, &brief).unwrap());
    // Y's part: the commit applies; the dropped part stays out until a copy comes, then it joins
    let _ = p.engine.ingest(&on(&pk, y), Vec::new());
    p.engine.reexamine().unwrap();
    assert!(p.engine.commit_ids().contains(&c) && p.engine.pending().is_empty(), "{:?}", p.engine.pending());
    assert_eq!(p.engine.get(&x, &brief).unwrap(), Some(s("older")), "counts as never received");
    assert!(flagged(&mut p));
    let _ = p.engine.ingest(&on(&pk, x), Vec::new());
    p.engine.reexamine().unwrap();
    assert_eq!(p.engine.get(&x, &brief).unwrap(), None, "joined value-less");
    assert!(!flagged(&mut p), "the body is back");
    let mut q = new();
    let _ = q.engine.ingest(&on(&pk, y), Vec::new());
    let _ = q.engine.ingest(&on(&pk, x), Vec::new());
    q.engine.reexamine().unwrap();
    assert_eq!(q.engine.state_digest(&x, &brief).unwrap(), p.engine.state_digest(&x, &brief).unwrap(), "as from the other order");
    assert_eq!(q.engine.get(&y, &ak("t:reg.0")).unwrap(), p.engine.get(&y, &ak("t:reg.0")).unwrap());
}

// spec/commits.md §4, §5: beside a part past its expiry, a part bad by itself or parked and a true one,
// with a relay's junk on two of the slots: in any order, each true copy delivered again at the end, the
// node reads alike, whatever it syncs.
#[test]
fn forged_parts_beside_a_part_past_expiry_alike_in_every_order_spec_commits_4() {
    use crate::common::*;
    for (n, how) in [Made::Bad, Made::Parked].into_iter().enumerate() {
        let mut f = forge_setup(83 + n as u64);
        let (x, y, z) = (f.x, f.y, f.z);
        let b = forge(&mut f, &[(x, "t:brief.0", Made::Good, Some(1000)), (y, "t:reg.0", how, None), (z, "t:reg.0", Made::Good, None)]);
        let now = osis_base::WallMs(f.lp.peers[0].engine.now().0 + 5000);
        let junk = |t: Tid, fill: u8| {
            let mut c = b.clone();
            let h = c.header.clone();
            c.parts.retain(|p| h.aspects[p.ai].tid == t);
            for p in &mut c.parts {
                p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![fill; 40])]));
            }
            c.encode()
        };
        let items = [cut(&b, &[x]), cut(&b, &[y]), cut(&b, &[z]), junk(x, 1), junk(z, 2)];
        let mut orders: Vec<Vec<usize>> = vec![Vec::new()];
        for i in 0..items.len() {
            orders = orders.iter().flat_map(|q| (0..=q.len()).map(move |at| { let mut o = q.clone(); o.insert(at, i); o })).collect();
        }
        for sync in [None, Some(x), Some(y), Some(z)] {
            let mut seen = std::collections::BTreeMap::<String, Vec<usize>>::new();
            for order in &orders {
                let mut p = Peer::new(FRESH, now).unwrap();
                if let Some(t) = sync {
                    p.engine.set_syncing(t, true).unwrap();
                }
                for pk in &f.setup {
                    let _ = p.engine.ingest(&pk.bytes, Vec::new());
                }
                for i in order {
                    let _ = p.engine.ingest(&items[*i], Vec::new());
                    p.engine.reexamine().unwrap();
                }
                for i in [0, 1, 2] {
                    let _ = p.engine.ingest(&items[i], Vec::new());
                    p.engine.reexamine().unwrap();
                }
                let got = format!("applied {} pending {:?} flags {:?} reads {:?} {:?} {:?}", p.engine.commit_ids().contains(&b.id()), p.engine.pending(), p.engine.suspects().unwrap().iter().map(|f| f.1.clone()).collect::<Vec<_>>(), p.engine.get(&x, &ak("t:brief.0")).unwrap(), p.engine.get(&y, &ak("t:reg.0")).unwrap(), p.engine.get(&z, &ak("t:reg.0")).unwrap());
                seen.entry(got).or_insert_with(|| order.clone());
            }
            assert_eq!(seen.len(), 1, "made {n}, sync {:?}: {seen:#?}", sync.map(|t| t == x));
        }
    }
}

// spec/commits.md §4: a commit on two synced things, one part away. Its author's removal on the other
// thing ends the wait in every order, whatever follows (a re-grant, the remover's own demotion making it
// fall: the commit that applied stays applied, so a node learning of them first applies it too); a
// removal whose frontier lists the commit leaves the delta valid: it waits.
#[test]
fn missing_delta_of_a_removed_author_any_order_spec_commits_4() {
    use crate::common::*;
    use osis_schema::Codec as _;
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Case {
        Regrant,
        Falls,
        Covered,
    }
    for case in [Case::Regrant, Case::Falls, Case::Covered] {
        let mut lp = net(3, 77);
        let (g, h) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
        let (bob, carol) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        for (t, who, r) in [(g, bob, Role::Write), (h, bob, Role::Write), (h, carol, Role::Admin)] {
            set_edge(&mut lp.peers[0].engine, t, who, Some(edge(r)), None);
        }
        lp.sync_all().unwrap();
        let base: Vec<_> = packages(&mut lp, 0);
        lp.advance(1_000);
        let mut m = Mutation::new();
        m.set(g, &REG, &s("by bob")).unwrap();
        m.set(h, &REG, &s("by bob")).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        let cp = packages(&mut lp, 1).into_iter().find(|p| p.id == c).unwrap();
        if case == Case::Covered {
            sync(&mut lp, 1, 2);
        }
        lp.advance(1_000);
        let revoke = |lp: &mut osis_node::local_peer::LocalPeer, by: usize, who: Tid| {
            let scope = osis_perm::DemotionScope { roles: [(who, [h].into())].into(), content: [(who, [h].into())].into() };
            let now = lp.peers[by].engine.now();
            let f = lp.peers[by].engine.frontier(&scope, now).unwrap();
            set_edge(&mut lp.peers[by].engine, h, who, None, Some(f.to_value()))
        };
        let d = revoke(&mut lp, 2, bob);
        let dp = packages(&mut lp, 2).into_iter().find(|p| p.id == d).unwrap();
        lp.advance(1_000);
        let after = match case {
            Case::Falls => revoke(&mut lp, 0, carol),
            _ => set_edge(&mut lp.peers[0].engine, h, bob, Some(edge(Role::Write)), None),
        };
        let ap = packages(&mut lp, 0).into_iter().find(|p| p.id == after).unwrap();
        let items = [on(&cp, g), dp.bytes.clone(), ap.bytes.clone()];
        for (k, order) in permutations(3).into_iter().enumerate() {
            let mut p = Peer::new(7000 + k as u64, lp.peers[0].engine.now()).unwrap();
            p.engine.set_syncing(g, true).unwrap();
            p.engine.set_syncing(h, true).unwrap();
            for pk in &base {
                p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
            }
            for i in order.iter() {
                let _ = p.engine.ingest(&items[*i], Vec::new());
                p.engine.reexamine().unwrap();
            }
            let want = if case == Case::Covered { "new" } else { "by bob" };
            assert_eq!(p.engine.get(&g, &reg()).unwrap(), Some(s(want)), "{case:?} {order:?}");
            assert_eq!(p.engine.get(&h, &reg()).unwrap(), Some(s("new")), "{case:?} {order:?}");
        }
    }
}

/// Random histories of writers' commits on two things, demotions, re-grants and demotions of the
/// demoter: what the removed-author rule of spec/commits.md §4 turns on.
fn removed_steps(rng: &mut Rng) -> Vec<Step> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    let mut out = vec![NewTop { by: 0 }, tick.clone()];
    for (t, holder, role) in [(1, 1, Role::Write), (1, 2, Role::Admin), (2, 1, Role::Write)] {
        out.push(Edge { by: 0, t, holder, role: Some(role) });
    }
    out.extend([Sync { from: 0, to: 1 }, Sync { from: 0, to: 2 }, tick.clone()]);
    for _ in 0..(6 + rng.below(10)) {
        let t = rng.below(2) as usize;
        let writer = 1 + rng.below(2) as usize;
        out.push(match rng.below(12) {
            0..=2 => Two { by: writer, a: t, b: 1 - t, v: rng.below(9) as u8 },
            3 => Demote { by: 2, t, holder: 1, at: rng.below(4) as u8, to_read: rng.below(2) == 0 },
            4 => Demote { by: 0, t, holder: writer, at: rng.below(4) as u8, to_read: rng.below(2) == 0 },
            5 => Edge { by: 0, t, holder: writer, role: Some(Role::Write) },
            6 => Roster { by: 0, t },
            7 => Sync { from: rng.below(3) as usize, to: rng.below(3) as usize },
            // Carol makes Bob an admin, he lowers her: a signer's grant that may fall
            8 => Edge { by: 2, t, holder: 1, role: Some(Role::Admin) },
            9 => Demote { by: 1, t, holder: 2, at: rng.below(4) as u8, to_read: rng.below(2) == 0 },
            10 => Edge { by: 1, t, holder: 2, role: Some(Role::Write) },
            _ => tick.clone(),
        });
        out.push(tick.clone());
    }
    out
}

/// What one seed of `removed_author_differential` found.
#[derive(Default)]
struct RemovedSeed {
    played: bool,
    /// Commits a reader syncing all applied with a part of theirs away.
    released: usize,
    /// Those that wait instead.
    waiting: usize,
    bad: Vec<String>,
}

fn removed_seed(seed: u64) -> RemovedSeed {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let steps = removed_steps(&mut rng);
    let Ok(played) = std::panic::catch_unwind(|| play(seed, &steps)) else { return RemovedSeed::default() };
    let ids: std::collections::BTreeSet<_> = played.packs.iter().map(|x| x.id).collect();
    let mut out = RemovedSeed { played: true, ..Default::default() };
    // a part of each commit on two things stays away, on one of them
    let away: Vec<(usize, Tid)> = (0..played.packs.len())
        .filter_map(|i| {
            let ts = things_of(&played, i);
            let b = CommitBlob::decode(&played.packs[i].bytes).unwrap();
            (b.header.kind == osis_commit::Kind::Content && ts.len() == 2 && rng.below(4) != 0).then(|| (i, ts[rng.below(2) as usize]))
        })
        .collect();
    if away.is_empty() {
        return out;
    }
    let cut = |i: usize| -> Vec<Vec<u8>> {
        let Some((_, t)) = away.iter().find(|x| x.0 == i) else { return vec![played.packs[i].bytes.clone()] };
        let b = CommitBlob::decode(&played.packs[i].bytes).unwrap();
        let mut x = b.clone();
        x.parts.retain(|p| b.header.aspects[p.ai].tid != *t);
        vec![x.encode()]
    };
    let read = |toks: &[(usize, Vec<u8>)], late: bool| {
        let mut p = Peer::new(FRESH, played.now).unwrap();
        for t in &played.things {
            p.engine.set_syncing(*t, true).unwrap();
        }
        for (i, b) in toks {
            let _ = p.engine.ingest(b, played.packs[*i].blobs.clone());
            p.engine.reexamine().unwrap();
        }
        let held = p.engine.pending();
        let pending = away.iter().filter(|(i, _)| held.iter().any(|x| x.0 == played.packs[*i].id)).count();
        if late {
            for (i, _) in &away {
                let _ = p.engine.ingest(&played.packs[*i].bytes, Vec::new());
                p.engine.reexamine().unwrap();
            }
        }
        let seen: Vec<(String, String)> = observe(&mut p.engine, &ids).into_iter().map(|(k, v)| (k, v.split(' ').filter(|w| !w.starts_with("deaths=")).collect::<Vec<_>>().join(" "))).collect();
        (seen, played.things.iter().map(|t| format!("{:?}", p.engine.roster(t))).collect::<Vec<_>>(), pending)
    };
    let toks: Vec<(usize, Vec<u8>)> = (0..played.packs.len()).flat_map(|i| cut(i).into_iter().map(move |b| (i, b))).collect();
    let whole: Vec<(usize, Vec<u8>)> = (0..played.packs.len()).map(|i| (i, played.packs[i].bytes.clone())).collect();
    let want = read(&toks, false);
    let joined = read(&whole, false);
    out.waiting = want.2;
    out.released = away.len() - want.2;
    let mut differs = |what: &str, got: &(Vec<(String, String)>, Vec<String>, usize), w: &(Vec<(String, String)>, Vec<String>, usize)| {
        if (&got.0, &got.1) != (&w.0, &w.1) {
            let first = got.0.iter().filter(|x| !w.0.contains(x)).map(|x| format!("got {x:?}")).chain(w.0.iter().filter(|x| !got.0.contains(x)).map(|x| format!("want {x:?}"))).collect::<Vec<_>>().join("; ");
            out.bad.push(format!("seed {seed} {what}: {}", first.chars().take(300).collect::<String>()));
        }
    };
    for _ in 0..8 {
        let mut order = toks.clone();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let got = read(&order, false);
        differs("any order, a part away", &got, &want);
        // the part arriving late: what they join to is the same as whole
        let got = read(&order, true);
        differs("the part comes", &got, &joined);
    }
    out
}

fn removed_replay(s: u64) -> String {
    format!("OSIS_REMOVED_START={s} OSIS_REMOVED_SEEDS=1 cargo test --workspace --test it parts::removed_author_differential_large_spec_commits_4 -- --ignored --exact")
}

// spec/commits.md §4: with a part of a commit on two things away, what a reader syncing both applies is
// alike in every order; the part coming late leaves what a reader holding it whole has. Reaches the
// removed-author rule: without it nothing is released.
#[test]
#[ignore]
fn removed_author_differential_large_spec_commits_4() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_REMOVED_START", "OSIS_REMOVED_SEEDS", 1..61);
    let n = seeds.range.end - seeds.range.start;
    let all = seeds.run("parts::removed_author_differential_large_spec_commits_4", removed_replay, removed_seed);
    let played_n = all.iter().filter(|s| s.played).count() as u64;
    let (released, waiting): (usize, usize) = (all.iter().map(|s| s.released).sum(), all.iter().map(|s| s.waiting).sum());
    let bad: Vec<&String> = all.iter().flat_map(|s| &s.bad).collect();
    eprintln!("{played_n} of {n} histories played, {released} commits released with a part away, {waiting} waiting");
    assert!(played_n > n / 2);
    assert!(n < 10 || (released > 0 && waiting > 0), "the histories reach the rule");
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.iter().take(12).map(|x| x.as_str()).collect::<Vec<_>>().join("\n"));
}


/// A lowering of `who` on `t` by peer `by` with a frontier listing nothing, as no writer here makes it.
fn forge_lowering(lp: &mut osis_node::local_peer::LocalPeer, by: usize, t: Tid, who: Tid) -> Vec<u8> {
    use crate::common::*;
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    use osis_schema::Codec as _;
    let roles = ak("roles.0");
    let v = Value::Map(std::collections::BTreeMap::from([(Value::Tid(who), edge(Role::Read).to_value())]));
    let author = lp.peers[by].engine.tid();
    let ts = osis_base::Ts::make(lp.peers[by].engine.now(), 0).unwrap();
    let own = Source::commit(osis_base::CommitId([0; 32]));
    let mut w = Writer::new(ts, own.clone(), 1 << 40);
    let f = create(&mut w, &osis_schema::core_schema().view(roles.as_str()).unwrap(), &v).unwrap();
    let r = w.range();
    let mut cx = writer_ctx(Form::Commit, Kind::Role, ts, author, r.lo, r.hi);
    cx.own = own;
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
    let mut aw = AspectWrite::new(t, roles.clone(), r.lo, r.hi, bytes);
    aw.retention = osis_commit::retention::write_retention(roles.as_str(), None, None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, author, author, Form::Commit);
    cb.aspects.push(aw);
    cb.frontier = Some(osis_schema::core_types::Frontier { commits: Default::default() }.to_value());
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[by].engine.identity().keys().signing, &Keys(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

// spec/commits.md §4: a lowering ends the wait for a removed author's delta only when signed by a
// possible admin of its thing. A plain holder's forgery on the thing or up its owner chain, after granting
// itself admin or not, tears no commit; an ex-admin's, and an admin through a group's or an owner's, ends
// it, before or after the commit, on the thing or on its owner.
#[test]
fn lowering_ends_a_wait_only_by_a_possible_admin_spec_commits_4() {
    use crate::common::*;
    use osis_schema::Codec as _;
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Who {
        Writer,
        Reader,
        OwnerReader,
        SelfGranted,
        Puppet,
        Stranger,
        ExAdmin,
        ByGroup,
        OnOwner,
    }
    let empty = || Some(osis_schema::core_types::Frontier { commits: Default::default() }.to_value());
    for who in [Who::Writer, Who::Reader, Who::OwnerReader, Who::SelfGranted, Who::Puppet, Who::Stranger, Who::ExAdmin, Who::ByGroup, Who::OnOwner] {
        for before in [true, false] {
            let mut lp = net(5, 77);
            let (x, o) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
            let y = {
                let p = lp.peer(0).unwrap();
                let mut m = Mutation::new();
                let t = p.engine.new_thing(&mut m, o);
                m.set(t, &REG, &s("new")).unwrap();
                p.commit(m).unwrap();
                t
            };
            let (bob, att, admin) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
            for (t, w, r) in [(x, bob, Role::Write), (y, bob, Role::Write), (y, admin, Role::Admin)] {
                set_edge(&mut lp.peers[0].engine, t, w, Some(edge(r)), None);
            }
            let e = &mut lp.peers[0].engine;
            match who {
                Who::Writer | Who::SelfGranted => drop(set_edge(e, y, att, Some(edge(Role::Write)), None)),
                Who::Reader | Who::Puppet => drop(set_edge(e, y, att, Some(edge(Role::Read)), None)),
                Who::Stranger => {}
                Who::OwnerReader => drop(set_edge(e, o, att, Some(edge(Role::Read)), None)),
                Who::ExAdmin => {
                    set_edge(e, y, att, Some(edge(Role::Admin)), None);
                    set_edge(e, y, att, None, empty());
                }
                // the group is an actor the owner made admin of `y`, `att` an admin of the group
                Who::ByGroup => {
                    set_edge(e, y, x, Some(edge(Role::Admin)), None);
                    set_edge(e, x, att, Some(edge(Role::Admin)), None);
                }
                Who::OnOwner => {
                    set_edge(e, o, bob, Some(edge(Role::Write)), None);
                    set_edge(e, o, att, Some(edge(Role::Admin)), None);
                }
            }
            lp.sync_all().unwrap();
            let base: Vec<_> = (0..5).flat_map(|i| packages(&mut lp, i)).collect();
            lp.advance(1_000);
            let mut extra = Vec::new();
            if who == Who::SelfGranted {
                let v = Value::Map(std::collections::BTreeMap::from([(Value::Tid(att), edge(Role::Admin).to_value())]));
                extra.push(crate::validity::forge_role_commit(&mut lp, 2, y, &ak("roles.0"), &v, 1 << 39));
                lp.advance(1_000);
            }
            // a reader names a sockpuppet admin, the sockpuppet does the lowering
            let by = if who == Who::Puppet {
                let v = Value::Map(std::collections::BTreeMap::from([(Value::Tid(lp.peers[4].engine.tid()), edge(Role::Admin).to_value())]));
                extra.push(crate::validity::forge_role_commit(&mut lp, 2, y, &ak("roles.0"), &v, 1 << 39));
                lp.advance(1_000);
                4
            } else {
                2
            };
            let forged = forge_lowering(&mut lp, by, if who == Who::OnOwner { o } else { y }, bob);
            lp.advance(1_000);
            let mut m = Mutation::new();
            m.set(x, &REG, &s("by bob")).unwrap();
            m.set(y, &REG, &s("by bob")).unwrap();
            let c = lp.peers[1].commit(m).unwrap().unwrap();
            let cp = packages(&mut lp, 1).into_iter().find(|p| p.id == c).unwrap();
            let mut p = Peer::new(7000, lp.peers[0].engine.now()).unwrap();
            p.engine.set_syncing(x, true).unwrap();
            p.engine.set_syncing(y, true).unwrap();
            for pk in &base {
                let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
            }
            for b in &extra {
                let _ = p.engine.ingest(b, Vec::new());
            }
            let part = on(&cp, x);
            for b in if before { [&forged, &part] } else { [&part, &forged] } {
                let _ = p.engine.ingest(b, Vec::new());
                p.engine.reexamine().unwrap();
            }
            let want = if matches!(who, Who::ExAdmin | Who::ByGroup | Who::OnOwner) { "by bob" } else { "new" };
            assert_eq!(p.engine.get(&x, &reg()).unwrap(), Some(s(want)), "{who:?} before={before}");
        }
    }
}

// spec/commits.md §4: the signer's admin may fall with its grant left out by the frontier that fells its
// granter, so that on the final timeline it never held admin: a possible admin all the same, in every order.
#[test]
fn lowering_by_one_whose_grant_fell_alike_in_every_order_spec_commits_4() {
    use crate::common::*;
    use osis_schema::Codec as _;
    let mut lp = net(4, 91);
    let (x, y) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let (bob, carol, z) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    for (t, w, r) in [(x, bob, Role::Write), (y, bob, Role::Write), (y, z, Role::Admin)] {
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(r)), None);
    }
    lp.sync_all().unwrap();
    let base: Vec<_> = (0..4).flat_map(|i| packages(&mut lp, i)).collect();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(x, &REG, &s("by bob")).unwrap();
    m.set(y, &REG, &s("by bob")).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    let cp = packages(&mut lp, 1).into_iter().find(|p| p.id == c).unwrap();
    lp.advance(1_000);
    let g = set_edge(&mut lp.peers[3].engine, y, carol, Some(edge(Role::Admin)), None);
    let gp = packages(&mut lp, 3).into_iter().find(|p| p.id == g).unwrap();
    sync(&mut lp, 3, 2);
    lp.advance(1_000);
    let lowering = forge_lowering(&mut lp, 2, y, bob);
    lp.advance(1_000);
    let fall = set_edge(&mut lp.peers[0].engine, y, z, None, Some(osis_schema::core_types::Frontier { commits: Default::default() }.to_value()));
    let fp = packages(&mut lp, 0).into_iter().find(|p| p.id == fall).unwrap();
    let items = [on(&cp, x), gp.bytes.clone(), lowering, fp.bytes.clone()];
    for (k, order) in permutations(4).into_iter().enumerate() {
        let mut p = Peer::new(7000 + k as u64, lp.peers[0].engine.now()).unwrap();
        p.engine.set_syncing(x, true).unwrap();
        p.engine.set_syncing(y, true).unwrap();
        for pk in &base {
            let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        for i in order.iter() {
            let _ = p.engine.ingest(&items[*i], Vec::new());
            p.engine.reexamine().unwrap();
        }
        assert_eq!(p.engine.get(&x, &reg()).unwrap(), Some(s("by bob")), "{order:?}");
    }
}

// spec/commits.md §4: a ledger entry that lowers its holder only as far as the role the delta needs lowers nothing here, as with the role commit; one below it does.
#[test]
fn ledger_entry_counts_only_below_the_role_needed_spec_commits_4() {
    use crate::common::*;
    use osis_schema::Codec as _;
    for (to, want) in [(Role::Write, "new"), (Role::Read, "by bob")] {
        let mut lp = net(2, 79);
        let (x, y) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
        let bob = lp.peers[1].engine.tid();
        set_edge(&mut lp.peers[0].engine, x, bob, Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, y, bob, Some(edge(Role::Admin)), None);
        lp.sync_all().unwrap();
        let base: Vec<_> = (0..2).flat_map(|i| packages(&mut lp, i)).collect();
        lp.advance(1_000);
        let mut m = Mutation::new();
        m.set(x, &REG, &s("by bob")).unwrap();
        m.set(y, &REG, &s("by bob")).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        let cp = packages(&mut lp, 1).into_iter().find(|p| p.id == c).unwrap();
        lp.advance(1_000);
        set_edge(&mut lp.peers[0].engine, y, bob, Some(edge(to)), Some(osis_schema::core_types::Frontier { commits: Default::default() }.to_value()));
        lp.advance(1_000);
        let snap = *lp.peers[0].engine.roster_snapshot(&y, None).unwrap().commits.last().unwrap();
        let sp = packages(&mut lp, 0).into_iter().find(|p| p.id == snap).unwrap();
        let mut p = Peer::new(7000, lp.peers[0].engine.now()).unwrap();
        p.engine.set_syncing(x, true).unwrap();
        p.engine.set_syncing(y, true).unwrap();
        for pk in &base {
            let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        let _ = p.engine.ingest(&sp.bytes, sp.blobs.clone());
        let _ = p.engine.ingest(&on(&cp, x), Vec::new());
        p.engine.reexamine().unwrap();
        assert_eq!(p.engine.get(&x, &reg()).unwrap(), Some(s(want)), "to {to:?}");
    }
}
