//! Delete keys at a node keeping S unread (spec/crypto.md §7, spec/sync-ids.md §6 Delete): such
//! a store cannot judge validity, so it checks a Delete by levels against the commitments the
//! blob's prefix bears, one signature per commitment group, under the head's sync or write key.
//! Each test hands node 1's store (it keeps S unread) the Delete a node would sign from what it
//! holds (`by_levels`, as the product's reader signs one) or one forged from keys it holds, and
//! reads the store's answer: what a holder of the keys can do there whatever the purge rules say
//! (notes/purge-model.md, Delete keys). Worlds: deletes.rs's `three` (node 0 admin, node 1
//! keeping thing 0 unread, node 2 a writer) and `four` (node 3 a second writer); `two_things`
//! adds thing 1 to `three`.

use crate::harness::Step::*;
use crate::harness::history::{Gives, Holder, three};
use crate::harness::{World, fixture_with, play};
use osis_base::{Ak, BlobId, CommitId, PurgeBy, SyncId, Tid, Value};
use osis_blob::{DeleteItem, Level};
use osis_crypto::{DeleteSecret, RoleKey, SigningSecret};
use osis_engine::Mutation;
use osis_proto::{Code, Msg, encode_frame};
use osis_sync::Out;

/// The role keys node `by` holds for node 1's head of S (thing `t`'s).
fn head_keys(w: &mut World, by: usize, t: Tid, s: &SyncId) -> osis_engine::sync_ids::HeadKeys {
    let head = w.store(1).head(s).unwrap().expect("node 1 keeps S");
    w.engine(by).head_keys(&t, &head).unwrap()
}

/// The head role key `r` in `keys`, as a Delete may use it (the sync key of an established epoch).
fn role(keys: &osis_engine::sync_ids::HeadKeys, r: RoleKey) -> Option<SigningSecret> {
    match r {
        RoleKey::Write => keys.write.clone(),
        RoleKey::Sync if keys.sync_established => keys.sync.clone(),
        _ => None,
    }
}

/// The Delete by levels of blob `b` that node `by` signs from what it holds (its `DeleteBasis`
/// and head keys, `osis_blob::cover_levels`), as osis-sync's reader does; `None` where no choice
/// of its keys covers every commitment group.
fn by_levels(w: &mut World, by: usize, t: Tid, s: &SyncId, b: &BlobId) -> Option<DeleteItem> {
    let keys = head_keys(w, by, t, s);
    let basis = w.engine(by).blob_delete_basis(b)?;
    let dks = osis_blob::cover_levels(&basis.prefix, &basis.blind, &basis.held, |r| role(&keys, r).is_some())?;
    let levels: Vec<Level> = dks.iter().map(|x| x.0).collect();
    let key = role(&keys, osis_blob::key_for_levels(&levels).ok()?)?;
    DeleteItem::sign_by(&key, &dks, basis.prefix.salt(), &basis.blind, s, *b).ok()
}

/// A Delete of `b` under `s` signed by `dks` and the head sync key in `keys`, whatever the blob's
/// prefix: `salt` and `blind` those of a blob of the same commit node `by` holds (`of`).
fn forged(w: &mut World, by: usize, of: &BlobId, keys: &osis_engine::sync_ids::HeadKeys, dks: &[(Level, &DeleteSecret)], s: &SyncId, b: &BlobId) -> DeleteItem {
    let basis = w.engine(by).blob_delete_basis(of).expect("the forger holds a blob");
    let key = role(keys, RoleKey::Sync).expect("the forger holds the head sync key");
    DeleteItem::sign_by(&key, dks, basis.prefix.salt(), &basis.blind, s, *b).unwrap()
}

/// Node 1's store takes `item` under `s` by a store credential (`Store::take_delete`).
fn take(w: &World, s: &SyncId, item: DeleteItem) -> Code {
    w.store(1).clone().take_delete(s, &[item], true).unwrap()[0]
}

/// Node `from` sends node 1 a Delete of `items` under `s` as a peer's frame on a connection up
/// between them, and the world delivers it: node 1's session and its Delete handler
/// (`inbox::serve`: the connection's credential for S, then the store) judge it as any peer's.
/// The reply answers an id `from`'s session never used, which it drops; tests read the store.
fn over_wire(w: &mut World, from: usize, s: &SyncId, items: Vec<DeleteItem>) {
    let conn = w.links_of(from).into_iter().find(|(_, j)| *j == 1).map(|(c, _)| c).expect("a connection up to node 1");
    let m = Msg::Delete { id: 0x3fff_0000, sync_id: *s, items };
    w.apply_as(from, vec![Out::Send(conn, encode_frame(&m.encode()))]);
    w.flush();
}

/// The level-`l` delete secret node `by` holds for blob `b` (from its `DeleteBasis`).
fn secret(w: &mut World, by: usize, b: &BlobId, l: Level) -> DeleteSecret {
    w.engine(by).blob_delete_basis(b).unwrap().held.into_iter().find(|x| x.0 == l).expect("held at that level").1
}

/// Node `i` writes `(ak, by)` pairs of thing `t` in one commit.
fn write(w: &mut World, i: usize, t: Tid, parts: &[(&str, PurgeBy)]) -> CommitId {
    w.write(i, |e| {
        let mut m = Mutation::new();
        for (ak, by) in parts {
            let ak = Ak::new(*ak).unwrap();
            m.set(t, &ak, &Value::Str(format!("by {i}"))).unwrap().purge_by(t, &ak, *by).unwrap();
        }
        e.commit(m).unwrap().unwrap()
    })
}

/// Node 1's one entry under `s` of commit `c` (blobs node `by` opens to `c`).
fn entry(w: &mut World, by: usize, s: &SyncId, c: &CommitId) -> BlobId {
    let es = w.store(1).entries(s).unwrap();
    let bs: Vec<BlobId> = es.into_iter().filter(|e| w.engine(by).blob_commit(&e.blob) == Some(*c)).map(|e| e.blob).collect();
    assert_eq!(bs.len(), 1, "node 1 holds one blob of the commit");
    bs[0]
}

fn held(w: &World, s: &SyncId, b: &BlobId) -> bool {
    w.store(1).entry(s, b).unwrap().is_some()
}

/// `three` (node 0 admin, node 1 keeping thing 0 unread, node 2 a writer).
fn world_of_three() -> (World, Tid, SyncId) {
    let (mut w, t, s) = three(Gives::Writes, 2);
    w.cap = 20_000;
    (w, t, s)
}

// spec/sync-ids.md §6 (Delete: one delete signature per commitment group of the blob's prefix),
// spec/crypto.md §7 (Levels): node 2's commit holds a delta only admins may purge (level 1) beside
// one its author may (levels 1, 2). The author holds no level-1 key, so no Delete it makes covers
// both groups: it signs none, and one by its level-2 key alone is refused, the blob kept. The
// admin's level-1 key covers both and deletes it. Fails with the store taking a Delete that
// covers some group.
#[test]
fn a_delete_by_levels_needs_the_right_over_every_delta_of_the_blob_spec_sync_ids_6() {
    let (mut w, t, s) = world_of_three();
    let c = write(&mut w, 2, t, &[("u:a.0", PurgeBy::Admin), ("u:b.0", PurgeBy::AuthorOrAdmin)]);
    w.run();
    let b = entry(&mut w, 2, &s, &c);
    assert_eq!(w.store(1).bytes(&b).unwrap().map(|x| osis_blob::clear_prefix(&x).unwrap().unwrap().groups().len()), Some(2), "two groups");
    assert!(by_levels(&mut w, 2, t, &s, &b).is_none(), "the author covers no choice of both groups");
    let keys = head_keys(&mut w, 2, t, &s);
    let two = secret(&mut w, 2, &b, 2);
    let alone = forged(&mut w, 2, &b, &keys, &[(2, &two)], &s, &b);
    assert_eq!(take(&w, &s, alone), Code::REFUSED, "a Delete covering one group");
    assert!(held(&w, &s, &b));
    let by_admin = by_levels(&mut w, 0, t, &s, &b).expect("the admin covers both");
    assert_eq!(take(&w, &s, by_admin), Code::OK);
    assert!(!held(&w, &s, &b), "the admin's Delete took it");
}

// spec/sync-ids.md §6 (Delete), spec/crypto.md §7 (Levels: level 2 the commit's purge author's):
// writer 3 holds no key of writer 2's write purgeable by its author or an admin: it signs no
// Delete of it, and one by its own level-2 key (its own purge author's, which covers its own
// write) or its write key alone is refused; writer 2's own Delete takes it. Fails with a store
// taking a level-2 signature under any key.
//
// spec/sync-ids.md §6 (Delete), spec/wire.md §11.2 (Delete): that refusal and the one above
// (`a_delete_by_levels_needs_the_right_over_every_delta_of_the_blob_spec_sync_ids_6`) as a peer
// sends them. Writer 2 sends node 1, in one Delete, its level-2 signature alone over a blob
// holding an admin-only delta beside its own (one group of two covered), then writer 3 sends its
// own level-2 key over writer 2's blob; each message also carries the sender's honest Delete of
// a write of its own (`by_levels`), which node 1 takes: S was open by a store credential on the
// connection, so the refusals are the levels'. Fails with the peer's path taking a Delete the
// store's own check refuses.
#[test]
fn a_party_without_the_right_signs_no_delete_a_store_or_its_peer_path_takes_spec_sync_ids_6() {
    let (mut w, t, s) = crate::deletes::four();
    let theirs = write(&mut w, 2, t, &[("u:a.0", PurgeBy::AuthorOrAdmin)]);
    let own = write(&mut w, 3, t, &[("u:b.0", PurgeBy::AuthorOrAdmin)]);
    let mixed = write(&mut w, 2, t, &[("u:f.0", PurgeBy::Admin), ("u:g.0", PurgeBy::AuthorOrAdmin)]);
    let own2 = write(&mut w, 2, t, &[("u:c.0", PurgeBy::AuthorOrAdmin)]);
    let theirs2 = write(&mut w, 2, t, &[("u:d.0", PurgeBy::AuthorOrAdmin)]);
    let own3 = write(&mut w, 3, t, &[("u:e.0", PurgeBy::AuthorOrAdmin)]);
    w.run();
    // at the store
    let (b, mine) = (entry(&mut w, 2, &s, &theirs), entry(&mut w, 3, &s, &own));
    assert!(by_levels(&mut w, 3, t, &s, &b).is_none(), "writer 3 covers nothing of writer 2's");
    let keys3 = head_keys(&mut w, 3, t, &s);
    let its = secret(&mut w, 3, &mine, 2);
    let item = forged(&mut w, 3, &mine, &keys3, &[(2, &its)], &s, &b);
    assert_eq!(take(&w, &s, item), Code::REFUSED, "another purge author's level-2 key");
    let item = forged(&mut w, 3, &b, &keys3, &[(2, &its)], &s, &b);
    assert_eq!(take(&w, &s, item), Code::REFUSED, "under the blob's own salt and blind");
    assert!(held(&w, &s, &b));
    let by_author = by_levels(&mut w, 2, t, &s, &b).expect("its author covers it");
    assert_eq!(take(&w, &s, by_author), Code::OK);
    assert!(!held(&w, &s, &b));
    // as a peer sends them
    let [bm, b2, bt, b3] = [mixed, own2, theirs2, own3].map(|c| entry(&mut w, if c == own3 { 3 } else { 2 }, &s, &c));
    let keys2 = head_keys(&mut w, 2, t, &s);
    let two = secret(&mut w, 2, &bm, 2);
    let alone = forged(&mut w, 2, &bm, &keys2, &[(2, &two)], &s, &bm);
    let honest2 = by_levels(&mut w, 2, t, &s, &b2).expect("writer 2 covers its own write");
    over_wire(&mut w, 2, &s, vec![alone, honest2]);
    assert!(!held(&w, &s, &b2), "writer 2's honest Delete went: S is open on the connection");
    assert!(held(&w, &s, &bm), "a Delete covering one group of two, sent by a peer");
    let keys3 = head_keys(&mut w, 3, t, &s);
    let its = secret(&mut w, 3, &b3, 2);
    let other = forged(&mut w, 3, &bt, &keys3, &[(2, &its)], &s, &bt);
    let honest3 = by_levels(&mut w, 3, t, &s, &b3).expect("writer 3 covers its own write");
    over_wire(&mut w, 3, &s, vec![other, honest3]);
    assert!(!held(&w, &s, &b3), "writer 3's honest Delete went");
    assert!(held(&w, &s, &bt), "another purge author's level-2 key, sent by a peer");
}

/// The blobs of commit `c` node 1 holds under `s` (as node 0 opens them).
fn blobs_of(w: &mut World, s: &SyncId, c: &CommitId) -> Vec<BlobId> {
    let es = w.store(1).entries(s).unwrap();
    es.into_iter().filter(|e| w.engine(0).blob_commit(&e.blob) == Some(*c)).map(|e| e.blob).collect()
}

/// Node 1 restarts and the world runs to quiet: its peers then hear what its store took
/// directly (a Delete handed to `Store::take_delete` tells no stream until the next pull).
fn told(w: &mut World) {
    w.power_off(1);
    w.power_on(1);
    w.run();
}

// spec/permissions.md §6 (a holder demoted since can still delete there what its old role allowed),
// spec/sync-judgement.md §4 (a node logs the body again once): node 2's write purgeable by its author is at node
// 1; node 0 lowers node 2 to read, which
// moves S's head but not its sync key (a read epoch). With its level-2 key (its own purge
// author's, never revoked) and the sync key it still holds, node 2 deletes the write at node 1
// with no purge: node 1 takes it. The holders log the body again once; node 2 deletes those too
// and they stay deleted (a second delete stands until the head moves or a part falls), while every
// reader still reads the write. A known weakness, pinned as today's behaviour
// (issues/demoted-writer-deletes-at-stores.md, notes/purge-model.md For Tess 4): a writer lowered
// to read, holding no author's right any more (spec/permissions.md §6), keeps its old writes out
// of a store that cannot read, so a reader syncing only through that store lacks them; nothing is
// erased while a holder keeps the body. The lowering rotated write (its write key is an earlier
// head's), not sync, and a level-2 Delete goes with the sync key. Node 2 removed outright
// instead: S's sync key rotates, and its old keys' Delete answers 9 (an earlier head's key): the
// blob stays.
#[test]
fn a_demoted_writers_old_keys_keep_its_writes_out_of_an_unread_store_spec_permissions_6() {
    for lower in [true, false] {
        let (mut w, t, s) = world_of_three();
        let c = write(&mut w, 2, t, &[("u:a.0", PurgeBy::AuthorOrAdmin)]);
        w.run();
        let b = entry(&mut w, 2, &s, &c);
        let (keys, two) = (head_keys(&mut w, 2, t, &s), secret(&mut w, 2, &b, 2));
        let blind = w.engine(2).blob_delete_basis(&b).unwrap().blind;
        let old = forged(&mut w, 2, &b, &keys, &[(2, &two)], &s, &b);
        let head = w.store(1).head_id(&s).unwrap();
        let removal = if lower { Lower(0, 0, Holder::Node(2), Gives::Reads) } else { Remove(0, 0, 2) };
        let _ = play(&mut w, &[removal, Run], String::new());
        assert_ne!(w.store(1).head_id(&s).unwrap(), head, "{lower}: the head moved");
        if !lower {
            assert_eq!(take(&w, &s, old), Code::NOT_HEAD_KEY, "removed: its keys are an earlier head's");
            told(&mut w);
            assert_eq!(blobs_of(&mut w, &s, &c), vec![b], "removed: the blob stays");
            continue;
        }
        assert!(head_keys(&mut w, 2, t, &s).write.is_none_or(|k| Some(k.verifying_key()) != keys.write.as_ref().map(|k| k.verifying_key())), "demoted: write rotated, its write key is an earlier head's");
        assert_eq!(take(&w, &s, old), Code::OK, "demoted: its old keys delete");
        told(&mut w);
        let again = blobs_of(&mut w, &s, &c);
        assert!(!again.is_empty() && !again.contains(&b), "the holders logged it again, fresh");
        let sync = role(&head_keys(&mut w, 2, t, &s), RoleKey::Sync).expect("a reader holds the sync key");
        for e in &again {
            let bytes = w.store(1).bytes(e).unwrap().unwrap();
            let salt = *osis_blob::clear_prefix(&bytes).unwrap().unwrap().salt();
            let item = DeleteItem::sign_by(&sync, &[(2, &two)], &salt, &blind, &s, *e).unwrap();
            assert_eq!(take(&w, &s, item), Code::OK, "its key deletes each logging again");
        }
        told(&mut w);
        w.advance(osis_base::format::MAX_DRIFT_MS + 60_000);
        w.run();
        assert!(blobs_of(&mut w, &s, &c).is_empty(), "a second delete stands: logged again once");
        for i in [0, 2] {
            assert_eq!(w.engine(i).get(&t, &Ak::new("u:a.0").unwrap()).unwrap(), Some(Value::Str("by 2".into())), "node {i} reads the write");
        }
    }
}

/// `three` with thing 1 (node 0 admin), which node 1 also keeps unread and node 2 reads: thing 0,
/// its sync ID, thing 1 and its sync ID. Built once per process (`fixture_with`).
fn two_things() -> (World, [(Tid, SyncId); 2]) {
    fixture_with("delete keys two things", || {
        let (mut w, _, _) = three(Gives::Writes, 2);
        w.cap = 2_000_000;
        let _ = play(&mut w, &[New(0), Grant(0, 1, 1, Gives::Syncs), Grant(0, 1, 2, Gives::Reads), Run, Run], String::new());
        let ts = [0, 1].map(|i| w.history.things[i].0);
        let out = ts.map(|t| (t, w.engine(0).sync_id_of(&t).unwrap().unwrap()));
        w.cap = 20_000;
        (w, out)
    })
}

// spec/sync-ids.md §6 (Delete: each signature verifying under that group's commitment),
// spec/crypto.md §7 (commitments computed for another thing are not the blob's),
// spec/wire.md §11.2: a delete's digest names its sync ID. Node 2, writer of thing 0 and reader of
// thing 1, holds a Delete node 1 takes of its own write `b` under S0. Handed under S1 it is refused; signed again for S1 with
// S1's head key it is refused (`b` is no entry there); a Delete of node 0's write on thing 1
// under S1 signed with every delete key node 2 holds for its own write (thing 0's and its purge
// author's) is refused. Every blob stays where it was. Fails with a store taking a Delete for an
// entry of another sync ID, or checking levels without the blob's own commitments.
#[test]
fn a_delete_naming_another_sync_ids_or_things_blob_is_refused_spec_sync_ids_6() {
    let (mut w, [(t0, s0), (t1, s1)]) = two_things();
    assert_ne!(s0, s1);
    let mine = write(&mut w, 2, t0, &[("u:a.0", PurgeBy::Writer)]);
    let theirs = write(&mut w, 0, t1, &[("u:b.0", PurgeBy::Writer)]);
    w.run();
    let (b, bu) = (entry(&mut w, 2, &s0, &mine), entry(&mut w, 0, &s1, &theirs));
    let valid = by_levels(&mut w, 2, t0, &s0, &b).expect("its author covers its own write");
    assert_eq!(take(&w, &s1, valid), Code::REFUSED, "a Delete for S0 handed under S1");
    let k1 = head_keys(&mut w, 2, t1, &s1);
    let all: Vec<(Level, DeleteSecret)> = w.engine(2).blob_delete_basis(&b).unwrap().held;
    assert_eq!(all.iter().map(|x| x.0).collect::<Vec<_>>(), vec![2, 3], "node 2 holds levels 2 and 3 of its write");
    let dks: Vec<(Level, &DeleteSecret)> = all.iter().map(|(l, d)| (*l, d)).collect();
    let item = forged(&mut w, 2, &b, &k1, &dks[..1], &s1, &b);
    assert_eq!(take(&w, &s1, item), Code::REFUSED, "S0's blob under S1");
    let salt = *osis_blob::clear_prefix(&w.store(1).bytes(&bu).unwrap().unwrap()).unwrap().unwrap().salt();
    let blind = w.engine(0).blob_delete_basis(&bu).unwrap().blind;
    let write_key = role(&k1, RoleKey::Write).or_else(|| role(&k1, RoleKey::Sync)).unwrap();
    let item = DeleteItem::sign_by(&write_key, &dks, &salt, &blind, &s1, bu).unwrap();
    assert_eq!(take(&w, &s1, item), Code::REFUSED, "thing 0's keys on thing 1's blob");
    assert!(held(&w, &s0, &b) && held(&w, &s1, &bu), "both blobs stay");
}

// spec/crypto.md §7 (Header list: a linked header list's chunks carry one empty group: no delete
// key covers them), spec/sync-ids.md §6 (Delete: an empty group is never covered),
// notes/a1-spec/README.md Open 8: node 2's commit's aspect list goes by link; node 2 purges every
// delta of it, so its level-2 key deletes the commit's blob at node 1, but the list's chunks stay
// there (they go with their header: by the delete key or at expiry), and a Delete of a chunk by
// that level-2 key is refused. Fails with a chunk committing to the commit's delete keys or a
// store taking a Delete of a blob with an empty group.
#[test]
fn nothing_deletes_a_header_lists_chunks_by_level_2_spec_crypto_7() {
    let (mut w, t, s) = world_of_three();
    let name = |i: usize| Ak::new(format!("u:{}{i:05}.0", "a".repeat(1000))).unwrap();
    let n = osis_base::format::CHUNK_THRESHOLD / 1000 + 4;
    let c = w.write(2, |e| {
        let mut m = Mutation::new();
        for i in 0..n {
            m.set(t, &name(i), &Value::Str("v".into())).unwrap().purge_by(t, &name(i), PurgeBy::AuthorOrAdmin).unwrap();
        }
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    assert!(w.engine(2).header(&c).unwrap().links.aspects.is_some(), "the aspect list goes by link");
    assert_eq!(w.engine(0).get(&t, &name(0)).unwrap(), Some(Value::Str("v".into())), "node 0 reads the write, its list resolved");
    let b = entry(&mut w, 2, &s, &c);
    let chunks: Vec<BlobId> = w.engine(2).header_list_blobs(&c).unwrap().into_iter().collect();
    assert!(!chunks.is_empty() && chunks.iter().all(|x| held(&w, &s, x)), "node 1 holds the list's chunks");
    for x in &chunks {
        let p = osis_blob::clear_prefix(&w.store(1).bytes(x).unwrap().unwrap()).unwrap().unwrap();
        assert!(p.groups().len() == 1 && p.groups()[0].is_empty(), "a chunk carries one empty group");
    }
    let (keys, two) = (head_keys(&mut w, 2, t, &s), secret(&mut w, 2, &b, 2));
    w.power_off(0);
    w.write(2, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &osis_schema::core_types::PURGE, &now).unwrap();
        for i in 0..n {
            m.purge_commit(c, t, name(i));
        }
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    assert!(!held(&w, &s, &b), "node 2's purge deleted the commit's blob at node 1");
    assert!(chunks.iter().all(|x| held(&w, &s, x)), "the list's chunks stay");
    for x in &chunks {
        let p = osis_blob::clear_prefix(&w.store(1).bytes(x).unwrap().unwrap()).unwrap().unwrap();
        let blind = w.engine(2).header(&c).unwrap().blind;
        let item = DeleteItem::sign_by(&role(&keys, RoleKey::Sync).unwrap(), &[(2, &two)], p.salt(), &blind, &s, *x).unwrap();
        assert_eq!(take(&w, &s, item), Code::REFUSED, "a level-2 Delete of a chunk");
    }
    assert!(chunks.iter().all(|x| held(&w, &s, x)));
}

// spec/crypto.md §7 (Levels: level 2 the write secret of the commit's one purge author),
// spec/permissions.md §6 (Purge author): node 0 makes thing X, gives node 2 write on it and X write
// on thing 0; node 2 writes thing 0 acting as X: X is the commit's purge author, not its signer.
// Its header's level-2 key is X's, not the one node 2's own writes list, and node 2, holding X's
// write secret, deletes the write at node 1 by it. (A split commit lists its one purge author's
// key alike: osis-commit `a_split_commit_lists_one_level_2_key`.) Fails with level 2 keyed to
// the signer.
#[test]
fn a_purge_author_other_than_the_signer_keys_level_2_spec_crypto_7() {
    let (mut w, t, s) = world_of_three();
    let _ = play(&mut w, &[New(0), Grant(0, 1, 2, Gives::Writes), Give(0, 0, Holder::Thing(1), Gives::Writes), Run], String::new());
    let x = w.history.things[1].0;
    let by = PurgeBy::AuthorOrAdmin;
    let c = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &Ak::new("u:a.0").unwrap(), &Value::Str("as X".into())).unwrap().purge_by(t, &Ak::new("u:a.0").unwrap(), by).unwrap();
        m.act_as(x);
        e.commit(m).unwrap().unwrap()
    });
    let own = write(&mut w, 2, t, &[("u:b.0", PurgeBy::AuthorOrAdmin)]);
    w.run();
    assert_eq!(w.engine(0).commit_purge_author(&c), Some(x), "X is its purge author");
    let level_2 = |w: &mut World, c: &CommitId| w.engine(0).header(c).unwrap().keys.iter().find(|k| k.level == 2).map(|k| k.key);
    assert!(level_2(&mut w, &c).is_some() && level_2(&mut w, &c) != level_2(&mut w, &own), "X's level-2 key, not the signer's own");
    assert_eq!(w.engine(0).get(&t, &Ak::new("u:a.0").unwrap()).unwrap(), Some(Value::Str("as X".into())), "the write stands");
    let b = entry(&mut w, 2, &s, &c);
    let item = by_levels(&mut w, 2, t, &s, &b).expect("node 2 holds X's write secret");
    assert_eq!(take(&w, &s, item), Code::OK);
    assert!(!held(&w, &s, &b));
}
