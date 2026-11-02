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
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
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
    let own = Source::node(author);
    let mut w = Writer::new(ts, own.clone(), 1000);
    let view = osis_crdt::AnyView;
    let f = create(&mut w, &view, &s("ok")).unwrap();
    let r = w.range();
    let mut cx = writer_ctx(Kind::Content, ts, author, r.lo, r.hi);
    cx.own = own;
    let good = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
    let parked = osis_base::encode(&Value::List(vec![Value::Bytes(vec![0; 16]), Value::List(vec![]), Value::List(vec![]), Value::List(vec![Value::Int(99)])]));
    let mut cb = CommitBuilder::new(Kind::Content, ts, author, author, Form::Node);
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
    let mut held = osis_keys::ActorEpochs::default();
    held.read.set_established(osis_keys::Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
    let rot = osis_keys::rotate(&h, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &osis_keys::Names::default(), &mut osis_crypto::SeededRng::from_u64(5)).unwrap();
    let boxed = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
    let secrets = osis_base::Ak::new("secrets.0").unwrap();
    let author = e.tid();
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    let view = osis_schema::core_schema().view(secrets.as_str()).unwrap();
    let own = Source::commit(osis_base::CommitId([0; 32]));
    let mut w = Writer::new(ts, own.clone(), 1);
    let f = create(&mut w, &view, &boxed).unwrap();
    let r = w.range();
    let mut cx = writer_ctx(Kind::Role, ts, author, r.lo, r.hi);
    cx.own = own;
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
    for (name, order) in [("G first", vec![&one, &two]), ("H first", vec![&two, &one]), ("together", vec![&whole])] {
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
        assert!(e.commit_ids().contains(&blob.id()), "G's part applied");
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

// issues/bad-part-whole-reject.md: a part that hashes to its entry but does not decode rejects
// the whole blob when it arrives with another part, and only itself when it arrives alone.
#[test]
#[ignore]
fn repro_bad_part_together_or_split_spec_commits_4() {
    use crate::common::*;
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    let mut lp = net(2, 65);
    let (g, h) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let setup = packages(&mut lp, 0);
    lp.peers[0].clock.advance(10);
    let e = &mut lp.peers[0].engine;
    let recs = vec![e.get_typed(&g, &osis_schema::core_types::CREATED).unwrap().unwrap(), e.get_typed(&h, &osis_schema::core_types::CREATED).unwrap().unwrap()];
    let author = e.tid();
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    let own = Source::node(author);
    let mut w = Writer::new(ts, own.clone(), 1000);
    let f = create(&mut w, &osis_crdt::AnyView, &s("ok")).unwrap();
    let r = w.range();
    let mut cx = writer_ctx(Kind::Content, ts, author, r.lo, r.hi);
    cx.own = own;
    let good = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
    let bad = osis_base::encode(&Value::List(vec![Value::Int(1)]));
    let mut cb = CommitBuilder::new(Kind::Content, ts, author, author, Form::Node);
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
        out.push(match rng.below(14) {
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
            _ => Advance { who: None, ms: 1000 },
        });
    }
    out
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

#[test]
#[ignore]
fn parts_differential_large_spec_commits_4() {
    let (from, n) = (std::env::var("OSIS_PARTS_START").ok().and_then(|x| x.parse().ok()).unwrap_or(1u64), std::env::var("OSIS_PARTS_SEEDS").ok().and_then(|x| x.parse().ok()).unwrap_or(150u64));
    let mut bad = Vec::new();
    let mut played_n = 0;
    for seed in from..from + n {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let steps = diff_steps(&mut rng);
        // a scripted step may be refused after a demotion
        let Ok(played) = std::panic::catch_unwind(|| play(seed, &steps)) else { continue };
        played_n += 1;
        let ids: std::collections::BTreeSet<_> = played.packs.iter().map(|x| x.id).collect();
        let later: Vec<usize> = (0..played.packs.len()).collect();
        for variant in 0..6 {
            let hidden: Vec<usize> = later.iter().copied().filter(|_| variant > 0 && rng.below(5) == 0).collect();
            let sync: Vec<Tid> = played.things.iter().copied().filter(|_| variant % 2 == 1 && rng.below(2) == 0).collect();
            let keep: Vec<usize> = later.iter().copied().filter(|i| !hidden.contains(i)).collect();
            let read = |toks: &[Vec<u8>], blobs: &[usize], toggles: Option<&[(usize, Tid, bool)]>| {
                let mut p = Peer::new(FRESH, played.now).unwrap();
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
                    let _ = p.engine.ingest(b, played.packs[blobs[at]].blobs.clone());
                }
                for t in sync.iter() {
                    p.engine.set_syncing(*t, true).unwrap();
                }
                p.engine.reexamine().unwrap();
                let roster: Vec<String> = played.things.iter().map(|t| format!("{:?}", p.engine.roster(t))).collect();
                // first and last deaths may date later by order (spec/commits.md §5)
                let seen: Vec<(String, String)> = observe(&mut p.engine, &ids).into_iter().map(|(k, v)| (k, v.split(' ').filter(|w| !w.starts_with("deaths=")).collect::<Vec<_>>().join(" "))).collect();
                (seen, roster)
            };
            let whole: Vec<Vec<u8>> = keep.iter().map(|i| played.packs[*i].bytes.clone()).collect();
            let (want, want_r) = read(&whole, &keep, None);
            for _ in 0..5 {
                let mut toks: Vec<(usize, Vec<u8>)> = keep.iter().flat_map(|i| cuts(&played, *i).into_iter().map(move |b| (*i, b))).collect();
                for i in (1..toks.len()).rev() {
                    toks.swap(i, rng.below(i as u64 + 1) as usize);
                }
                let (is, bs): (Vec<usize>, Vec<Vec<u8>>) = toks.into_iter().unzip();
                let (got, _) = read(&bs, &is, None);
                if got != want {
                    let first = got.iter().zip(&want).find(|(a, b)| a != b).map(|x| format!("{x:?}"));
                    bad.push(format!("seed {seed} variant {variant} fixed sync: {}", first.unwrap_or_default().chars().take(300).collect::<String>()));
                }
                // the sync set arriving during delivery, same in the end
                let toggles: Vec<(usize, Tid, bool)> = sync.iter().map(|t| (rng.below(bs.len() as u64 + 1) as usize, *t, true)).collect();
                let (_, r) = read(&bs, &is, Some(&toggles));
                if r != want_r {
                    let first = r.iter().zip(&want_r).find(|(a, b)| a != b).map(|x| format!("{x:?}"));
                    bad.push(format!("seed {seed} variant {variant} changing sync, roster: {}", first.unwrap_or_default().chars().take(300).collect::<String>()));
                }
            }
        }
    }
    eprintln!("{played_n} of {n} histories played");
    assert!(played_n > n / 2);
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.iter().take(12).cloned().collect::<Vec<_>>().join("\n"));
}

// issues/waiting-part-poison.md: a relay's junk part on a thing whose record is away cannot be
// hash-checked, sits in the pending copy, and keeps out the true part; when the record comes the
// junk goes as a bad part and the true part is gone with it.
#[test]
#[ignore]
fn repro_waiting_part_poison_spec_commits_4() {
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
    p.engine.ingest(&junk.encode(), Vec::new()).unwrap();
    p.engine.ingest(&good, Vec::new()).unwrap();
    p.engine.ingest(&played.packs[rec].bytes, played.packs[rec].blobs.clone()).unwrap();
    p.engine.reexamine().unwrap();
    assert_eq!(p.engine.get(&h, &reg()).unwrap(), v("v7"));
}

// spec/commits.md §4 (`examine`'s invariant): a commit on two synced things, the H part expired
// (counts as held) with its pages away. The G part first applies the commit, then the H part
// waits alone; the H part first holds the commit whole, for good: the pages left with the expiry.
#[test]
#[ignore]
fn repro_counted_as_held_part_order_spec_commits_4() {
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
