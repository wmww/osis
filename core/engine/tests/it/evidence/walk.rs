//! The derivation against the real walk (osis-perm `paths`), not the model: a reader holding a
//! sync ID's bodies plus exactly the copies `Evidence` says it requires judges each body as the node
//! holding everything (draft notes/a2-spec/permissions.md §4; spec/sync-judgement.md §1). Commits
//! are built by hand with real stated paths: engine role commits state the Interim empty path and
//! the engine does not run the walk yet (A1 step 3), so this is the walk's plain input, with a
//! minimal adapter (`Node`) from it to the derivation's `Part`s; chained-ness per write from the
//! walk's first chained keys per edge (no invite grants: the walk does not report an invite
//! grant's chained-ness, notes/evidence-derivation.md).
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts, WallMs};
use osis_engine::evidence::{Config, CopyId, Evidence, Gives, Hop, Kind, Need, Part, Write};
use osis_perm::paths::{Commit, Content, Delta, DeltaClass, EdgeWrite, Key, List, Part as PPart, PartKind, Paths};
use osis_perm::{Edge, Frontier, WriteId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const X: u8 = 1;
const Y: u8 = 2;
const K: u8 = 3;
const Q: u8 = 4;
const Z: u8 = 5;
const A: u8 = 10;
const B: u8 = 11;
const D: u8 = 12;
const E: u8 = 13;

fn tid(t: u8) -> Tid {
    let mut b = [0u8; 15];
    b[0] = t;
    Tid::from_bytes(b)
}
fn cid(i: u32) -> CommitId {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&i.to_be_bytes());
    CommitId(b)
}
fn ts(t: u64) -> Ts {
    Ts::make(WallMs(t), 0).unwrap()
}

/// A world: records (thing → mint admin) and commits in writing order.
struct World {
    records: BTreeMap<Tid, Tid>,
    commits: Vec<Commit>,
}

impl World {
    fn new(records: &[(u8, u8)]) -> World {
        World { records: records.iter().map(|&(m, t)| (tid(t), tid(m))).collect(), commits: vec![] }
    }
    fn push(&mut self, t: u64, signer: u8, parts: Vec<PPart>) -> CommitId {
        let id = cid(self.commits.len() as u32 + 1);
        self.commits.push(Commit { id, ts: ts(t), signer: tid(signer), parts });
        id
    }
    /// An edge write along the empty path (the signer the target's mint admin, or holding admin
    /// on it directly).
    fn set(&mut self, t: u64, signer: u8, on: u8, holder: u8, role: Option<Role>, frontier: &[CommitId]) -> CommitId {
        let value = role.map(Edge::new);
        // A1's single list: each commit in the leaf of every thing it writes
        let entries = frontier.iter().flat_map(|x| self.commits.iter().filter(move |c| c.id == *x).flat_map(|c| c.parts.iter().map(|p| (p.on, c.id))));
        let frontier = Some(Arc::new(List::new(entries.collect::<Vec<_>>())));
        self.push(t, signer, vec![edge_part(&[], on, holder, value, frontier)])
    }
    fn content(&mut self, t: u64, signer: u8, path: &[u8], on: u8) -> CommitId {
        self.push(t, signer, vec![content_part(path, on)])
    }
    fn vouch(&mut self, t: u64, signer: u8, on: u8, removal: CommitId, list: &[CommitId]) -> CommitId {
        self.push(t, signer, vec![PPart { on: tid(on), path: vec![], direct: 0, kind: PartKind::Vouch { removal, list: Frontier::new(list.iter().copied()) } }])
    }
}

fn edge_part(path: &[u8], on: u8, holder: u8, value: Option<Edge>, frontier: Option<Arc<List>>) -> PPart {
    PPart { on: tid(on), path: path.iter().map(|&t| tid(t)).collect(), direct: 0, kind: PartKind::Edge(EdgeWrite { holder: tid(holder), value, frontier, remains: None, adminless: false }) }
}
fn content_part(path: &[u8], on: u8) -> PPart {
    let delta = Delta { aspect: Ak::new("doc.0").unwrap(), needs: Role::Write, purge_author: 0, retention: PurgeBy::AuthorOrAdmin, class: DeltaClass::Plain };
    PPart { on: tid(on), path: path.iter().map(|&t| tid(t)).collect(), direct: 0, kind: PartKind::Delta(delta) }
}

/// The edges joining path members (draft §1 Hops): record edges down a mint chain, else direct.
fn joins(records: &BTreeMap<Tid, Tid>, p: Tid, q: Tid) -> Vec<(Tid, Tid)> {
    let mut down = vec![];
    let mut t = q;
    while let Some(&m) = records.get(&t) {
        down.push((m, t));
        if m == p {
            down.reverse();
            return down;
        }
        t = m;
    }
    vec![(p, q)]
}

/// A part's hops: members [signer, path.., on] (a self-removal ends at its holder).
fn hops(records: &BTreeMap<Tid, Tid>, c: &Commit, p: &PPart) -> Vec<(Tid, Tid)> {
    let ak = *p.path.last().unwrap_or(&c.signer);
    let leave = matches!(&p.kind, PartKind::Edge(w) if w.holder == ak);
    let mut members = vec![c.signer];
    members.extend(&p.path);
    if !leave {
        members.push(p.on);
    }
    if !(p.on == c.signer && p.path.is_empty() && matches!(p.kind, PartKind::Delta(_))) {
        return members.windows(2).flat_map(|w| joins(records, w[0], w[1])).collect();
    }
    vec![]
}

/// The node holding `held` and what the derivation takes of it: one copy per (commit, thing),
/// chained-ness from the walk over `held`, each edge write's creation as given.
struct Node {
    paths: Paths,
    ev: Evidence<CommitId, Tid, Key>,
}

impl Node {
    fn new(w: &World, held: &[Commit], trust: BTreeSet<WriteId>, creations: &BTreeMap<WriteId, (CommitId, Tid)>, unit: &[u8]) -> Node {
        let paths = Paths::evaluate(&w.records, trust, held);
        let first = paths.chained();
        let mut ev = Evidence::new(Config { vouches: true, reach: false, keys_open: false });
        ev.add_sid(tid(D), tid(D));
        for &t in unit {
            ev.join(&tid(D), tid(t));
        }
        for c in held {
            let start = Key { ts: c.ts, signer: c.signer, commit: c.id, part: 0 };
            let mut by: BTreeMap<Tid, Vec<Part<CommitId, Tid, Key>>> = BTreeMap::new();
            for (i, p) in c.parts.iter().enumerate() {
                let hs = hops(&w.records, c, p);
                let record = |h: &(Tid, Tid)| w.records.get(&h.1) == Some(&h.0);
                // admin (slot 1) or write (slot 0) on each hop from a chained write of an earlier commit
                let has = |slot: usize| hs.iter().all(|h| record(h) || first.get(h).and_then(|f| f[slot]).is_some_and(|k| k < start));
                let (kind, chained) = match &p.kind {
                    PartKind::Edge(e) => {
                        assert!(e.value.is_none_or(|v| v.invite.is_none()), "no invites: the walk does not report an invite grant's chained-ness");
                        let leave = e.holder == *p.path.last().unwrap_or(&c.signer);
                        let finalize = e.value.is_none() && e.frontier.is_none() && !leave;
                        let role = e.value.map(|v| v.role);
                        let wr = Write {
                            holder: e.holder,
                            grant: role.filter(|_| !leave).map(Gives::role),
                            removal: role.is_none_or(|r| r < Role::Write) && !finalize,
                            gives_write: role.is_some_and(|r| r >= Role::Write),
                            gives_read: role.is_some_and(|r| r >= Role::Read) && !leave,
                            relies: e.remains,
                            creation: creations.get(&WriteId(c.id, i as u32)).copied(),
                        };
                        (Kind::Write(wr), if finalize { has(0) } else { has(1) })
                    }
                    PartKind::Vouch { removal, .. } => {
                        // keyed by the removal's copy on the vouch's thing (one-thing removals here)
                        (Kind::Vouch { keyed: (*removal, p.on) }, has(1))
                    }
                    PartKind::Delta(_) => (Kind::Content, false),
                };
                let pos = if matches!(p.kind, PartKind::Delta(_)) { Key::start(c.ts) } else { Key { part: i as u32, ..start } };
                // what the part needs of each hop: write for content (admin for an admin-only
                // aspect), write for a finalize, admin for any other edge-class part
                let need = match &p.kind {
                    PartKind::Delta(d) => Need::Role(d.needs),
                    PartKind::Edge(e) if e.value.is_none() && e.frontier.is_none() && e.holder != *p.path.last().unwrap_or(&c.signer) => Need::Role(Role::Write),
                    _ => Need::Role(Role::Admin),
                };
                let hops = Some(hs.iter().map(|&edge| Hop { edge, record: record(&edge), need }).collect());
                by.entry(p.on).or_default().push(Part { kind, hops, pos, chained });
            }
            for (t, parts) in by {
                ev.add((c.id, t), parts);
            }
        }
        Node { paths, ev }
    }

    fn required(&self) -> BTreeSet<CopyId<CommitId, Tid>> {
        self.ev.check().unwrap();
        self.ev.required(&tid(D)).unwrap().keys().copied().collect()
    }
}

/// Each edge write's creation: the first chained grant on its edge before it, over everything
/// written (the entry its reset names: a fact of the commit, the same at every node).
fn creations(w: &World) -> BTreeMap<WriteId, (CommitId, Tid)> {
    let p = Paths::evaluate(&w.records, BTreeSet::new(), &w.commits);
    let first = p.chained();
    let key = |c: &Commit, i: usize| Key { ts: c.ts, signer: c.signer, commit: c.id, part: i as u32 };
    let mut grants: Vec<(Key, (Tid, Tid), CommitId)> = vec![];
    for c in &w.commits {
        for (i, part) in c.parts.iter().enumerate() {
            if let PartKind::Edge(e) = &part.kind
                && e.value.is_some()
            {
                let start = Key { part: 0, ..key(c, i) };
                let hs = hops(&w.records, c, part);
                if hs.iter().all(|h| w.records.get(&h.1) == Some(&h.0) || first.get(h).and_then(|f| f[1]).is_some_and(|k| k < start)) {
                    grants.push((key(c, i), (e.holder, part.on), c.id));
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    for c in &w.commits {
        for (i, part) in c.parts.iter().enumerate() {
            if let PartKind::Edge(e) = &part.kind
                && let Some(g) = grants.iter().filter(|g| g.1 == (e.holder, part.on) && g.0 < key(c, i)).min_by_key(|g| g.0)
            {
                out.insert(WriteId(c.id, i as u32), (g.2, part.on));
            }
        }
    }
    out
}

/// The reader's held commits: every part on a unit thing, and each required copy's parts on its
/// thing; with each kept part's index in its full commit.
fn reader_set(w: &World, unit: &[u8], copies: &BTreeSet<CopyId<CommitId, Tid>>) -> (Vec<Commit>, BTreeMap<WriteId, WriteId>) {
    let mut out = vec![];
    let mut ids = BTreeMap::new();
    for c in &w.commits {
        let keep: Vec<usize> = (0..c.parts.len()).filter(|&i| unit.iter().any(|&t| tid(t) == c.parts[i].on) || copies.contains(&(c.id, c.parts[i].on))).collect();
        if keep.is_empty() {
            continue;
        }
        for (n, &i) in keep.iter().enumerate() {
            ids.insert(WriteId(c.id, i as u32), WriteId(c.id, n as u32));
        }
        out.push(Commit { parts: keep.iter().map(|&i| c.parts[i].clone()).collect(), ..c.clone() });
    }
    (out, ids)
}

/// Verdicts on the unit's parts: content and edge-class statuses, keyed by full `WriteId`.
fn verdicts(w: &World, p: &Paths, unit: &[u8], ids: Option<&BTreeMap<WriteId, WriteId>>) -> BTreeMap<WriteId, String> {
    let mut out = BTreeMap::new();
    for c in &w.commits {
        for (i, part) in c.parts.iter().enumerate() {
            if !unit.iter().any(|&t| tid(t) == part.on) {
                continue;
            }
            let full = WriteId(c.id, i as u32);
            let id = ids.map_or(full, |m| m[&full]);
            let v = match part.kind {
                PartKind::Delta(_) => format!("{:?}", p.content(&id)),
                _ => format!("{:?}", p.status(&id)),
            };
            out.insert(full, v);
        }
    }
    out
}

/// The writer holds everything; D's reader holds D's bodies and the copies the writer's derivation
/// requires: each body judged alike. Returns the required copies and the writer's verdicts.
fn reader_agrees(w: &World, unit: &[u8], trust: &[WriteId]) -> (BTreeSet<CopyId<CommitId, Tid>>, BTreeMap<WriteId, String>) {
    let cr = creations(w);
    let trust: BTreeSet<WriteId> = trust.iter().copied().collect();
    let writer = Node::new(w, &w.commits, trust.clone(), &cr, unit);
    let req = writer.required();
    let (held, ids) = reader_set(w, unit, &req);
    let rtrust = trust.iter().filter_map(|t| ids.get(t).copied()).collect();
    let reader = Node::new(w, &held, rtrust, &cr, unit);
    let wv = verdicts(w, &writer.paths, unit, None);
    let rv = verdicts(w, &reader.paths, unit, Some(&ids));
    assert_eq!(wv, rv, "required {req:?}");
    // the reader's own derivation over what it holds requires no more than it holds
    let rreq = reader.required();
    assert!(rreq.is_subset(&req), "reader requires {rreq:?}, writer {req:?}");
    (req, wv)
}

/// Verdicts of a reader holding D's bodies and `copies`.
fn reader_verdicts(w: &World, unit: &[u8], copies: &BTreeSet<CopyId<CommitId, Tid>>) -> BTreeMap<WriteId, String> {
    let (held, ids) = reader_set(w, unit, copies);
    verdicts(w, &Paths::evaluate(&w.records, BTreeSet::new(), &held), unit, Some(&ids))
}

fn valid() -> String {
    format!("{:?}", Some(Content::Valid(osis_perm::paths::By::Held)))
}

/// Z writes D through A on K's grant; X removes K keeping K's own write, dropping K's grant to Z;
/// Q vouches for that grant; X re-grants K, who writes again; Z's junk grant on A. D's reader
/// holding D's bodies and the required copies judges every body of D as the writer; less any one
/// of the copies a verdict reads, it does not.
#[test]
fn a_reader_holding_the_bodies_and_the_required_copies_judges_as_the_writer_spec_permissions_4() {
    let mut w = World::new(&[(X, A), (Y, D)]);
    w.set(1, Y, D, A, Some(Role::Write), &[]);
    let gk = w.set(1, X, A, K, Some(Role::Admin), &[]);
    let gq = w.set(1, X, A, Q, Some(Role::Admin), &[]);
    let gz = w.set(2, K, A, Z, Some(Role::Write), &[]);
    let cz = w.content(3, Z, &[A], D);
    let ck = w.content(3, K, &[A], D);
    let junk = w.set(4, Z, A, Q, Some(Role::Admin), &[]);
    let rm = w.set(5, X, A, K, None, &[ck]);
    let v = w.vouch(6, Q, A, rm, &[gz]);
    let rg = w.set(7, X, A, K, Some(Role::Write), &[]);
    let ck2 = w.content(8, K, &[A], D);
    let (req, wv) = reader_agrees(&w, &[D], &[]);
    let a = tid(A);
    let want: BTreeSet<_> = [gk, gq, gz, rm, v, rg].into_iter().map(|c| (c, a)).collect();
    assert_eq!(req, want);
    assert!(!req.contains(&(junk, a)));
    // Z's write valid by the vouch, K's first by the removal's list, its second by the re-grant
    for c in [cz, ck, ck2] {
        assert!(wv[&WriteId(c, 0)].contains("Valid"), "{c:?}: {wv:?}");
    }
    // each copy the verdicts read: a reader without it judges some body of D otherwise
    for c in [gk, gq, gz, rm, v, rg] {
        let less: BTreeSet<_> = req.iter().copied().filter(|x| x.0 != c).collect();
        assert_ne!(reader_verdicts(&w, &[D], &less), wv, "without {c:?}");
    }
}

/// The same world under a trust set (the node trusts K's grant to Z, which the removal drops): the
/// derivation reads no trust (evidence is a function of the held commits), and a reader trusting
/// the same write and holding D's bodies and the copies judges D as the writer; the copies are the
/// same as with no trust set.
#[test]
fn a_trust_set_moves_no_evidence_and_the_reader_under_it_judges_as_the_writer_spec_permissions_4() {
    let mut w = World::new(&[(X, A), (Y, D)]);
    w.set(1, Y, D, A, Some(Role::Write), &[]);
    w.set(1, X, A, K, Some(Role::Admin), &[]);
    let gz = w.set(2, K, A, Z, Some(Role::Write), &[]);
    let cz = w.content(3, Z, &[A], D);
    w.set(5, X, A, K, None, &[]);
    let (plain, pv) = reader_agrees(&w, &[D], &[]);
    let (trusted, tv) = reader_agrees(&w, &[D], &[WriteId(gz, 0)]);
    assert_eq!(plain, trusted);
    assert!(pv.contains_key(&WriteId(cz, 0)) && tv.contains_key(&WriteId(cz, 0)));
}

/// A path of three hops with churn: Z writes D along [B, A] (Z on B, B on A, A on D); Y lowers A on
/// D (to read) and grants it write again, X removes B on A and grants it again, between Z's writes:
/// the writes on A's and B's edges are required, and the reader judges as the writer.
#[test]
fn a_longer_path_with_churn_on_each_edge_spec_permissions_4() {
    let mut w = World::new(&[(X, A), (Y, D), (X, B)]);
    w.set(1, Y, D, A, Some(Role::Write), &[]);
    w.set(1, X, A, B, Some(Role::Write), &[]);
    w.set(1, X, B, Z, Some(Role::Write), &[]);
    w.content(2, Z, &[B, A], D);
    w.set(3, X, A, B, None, &[]);
    w.content(4, Z, &[B, A], D);
    w.set(5, X, A, B, Some(Role::Write), &[]);
    w.set(5, Y, D, A, Some(Role::Read), &[]);
    w.content(6, Z, &[B, A], D);
    w.set(7, Y, D, A, Some(Role::Write), &[]);
    w.content(8, Z, &[B, A], D);
    let (req, wv) = reader_agrees(&w, &[D], &[]);
    let things: BTreeSet<Tid> = req.iter().map(|c| c.1).collect();
    assert_eq!(things, BTreeSet::from([tid(A), tid(B)]));
    assert_eq!(req.len(), 4);
    // the later writes are valid by the re-grant rule, which reads the churn on the path's edges
    assert!(wv.values().filter(|v| v.contains("Regranted")).count() >= 2, "{wv:?}");
}

/// The split form: K writes D along [A] and E along [B] in one commit; D's reader holds the D part
/// and A's copies, never anything on B or the E part, and judges as the writer; E's reader the
/// reverse.
#[test]
fn a_split_commits_part_on_another_thing_is_neither_held_nor_required_spec_permissions_4() {
    let mut w = World::new(&[(X, A), (Y, D), (Y, B), (X, E)]);
    w.set(1, Y, D, A, Some(Role::Write), &[]);
    w.set(1, X, E, B, Some(Role::Write), &[]);
    let ga = w.set(1, X, A, K, Some(Role::Write), &[]);
    let gb = w.set(1, Y, B, K, Some(Role::Write), &[]);
    let split = w.push(2, K, vec![content_part(&[A], D), content_part(&[B], E)]);
    w.set(3, Y, B, K, None, &[]);
    let (req, wv) = reader_agrees(&w, &[D], &[]);
    assert_eq!(req, BTreeSet::from([(ga, tid(A))]));
    assert_eq!(wv[&WriteId(split, 0)], valid());
    // E's reader: the derivation for E's unit (sid D's actor reused, unit E)
    let (req_e, ve) = reader_agrees(&w, &[E], &[]);
    assert!(req_e.contains(&(gb, tid(B))) && !req_e.contains(&(ga, tid(A))), "{req_e:?}");
    assert!(ve[&WriteId(split, 1)].contains("Invalid"), "{ve:?}");
}

/// A node trusting a write no chain gives authority (Z, a writer, removing K on A): the walk leaves
/// it void, so it moves no verdict; it is no copy (unchained), and a reader not holding it, its
/// trust in it moot, judges as the writer. Trust never reaches evidence: only writes some walk
/// applies change verdicts under a trust set, and those are chained.
#[test]
fn a_trusted_write_no_chain_gives_authority_is_void_and_no_copy_spec_permissions_4() {
    let mut w = World::new(&[(X, A), (Y, D)]);
    w.set(1, Y, D, A, Some(Role::Write), &[]);
    let gk = w.set(1, X, A, K, Some(Role::Write), &[]);
    w.set(1, X, A, Z, Some(Role::Write), &[]);
    let junk = w.set(2, Z, A, K, None, &[]);
    let ck = w.content(3, K, &[A], D);
    let (req, wv) = reader_agrees(&w, &[D], &[WriteId(junk, 0)]);
    assert_eq!(req, BTreeSet::from([(gk, tid(A))]));
    assert_eq!(wv[&WriteId(ck, 0)], valid());
    let p = Paths::evaluate(&w.records, BTreeSet::from([WriteId(junk, 0)]), &w.commits);
    assert!(p.void_trusted().contains(&WriteId(junk, 0)));
}

/// Finding 9 under the walk: X removes K and Q from A in one commit; K writes D through [A]. D's
/// evidence holds the removal (on K's edge) and the creation of Q's entry its other part resets
/// (X's grant to Q, on no stated path); the reader holding them judges as the writer. The wait
/// itself (a removal applies only once each reset entry's creation is held, spec/permissions.md §2)
/// is the engine's (`apply::validity`), not the walk's: its engine test is owed
/// (notes/evidence-derivation.md, Left).
#[test]
fn f9_a_removal_of_two_holders_brings_both_creations_under_the_walk_spec_permissions_2() {
    let mut w = World::new(&[(X, A), (Y, D)]);
    w.set(1, Y, D, A, Some(Role::Write), &[]);
    let gk = w.set(1, X, A, K, Some(Role::Write), &[]);
    let gq = w.set(1, X, A, Q, Some(Role::Write), &[]);
    let ck = w.content(2, K, &[A], D);
    let fr = Some(Arc::new(List::new([(tid(D), ck)])));
    let rm = w.push(5, X, vec![edge_part(&[], A, K, None, fr.clone()), edge_part(&[], A, Q, None, fr)]);
    let ck2 = w.content(6, K, &[A], D);
    let (req, wv) = reader_agrees(&w, &[D], &[]);
    let a = tid(A);
    assert_eq!(req, BTreeSet::from([(gk, a), (gq, a), (rm, a)]));
    assert_eq!(wv[&WriteId(ck, 0)], format!("{:?}", Some(Content::Valid(osis_perm::paths::By::Listed))));
    assert!(wv[&WriteId(ck2, 0)].contains("Invalid"), "{wv:?}");
}
