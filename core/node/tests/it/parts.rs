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
