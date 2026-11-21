//! The engine's ciphertext door (`osis_store::CipherHost`): the engine holds and releases blobs
//! in the node's one store, in a transaction of the store's that it commits before its own. A
//! blob's bytes stay while the engine or any entry of any sync ID holds them; bytes the engine
//! holds make every entry naming them servable (`entries::bytes_arrived`).

use super::entries::{bytes_arrived, unref};
use super::{Inner, rows};
use osis_base::BlobId;
use osis_store::{Error, Shred, Transaction};
use std::sync::Arc;

type Res<T> = std::result::Result<T, Error>;

fn to_store(e: crate::types::Error) -> Error {
    e.into_store("sync store")
}

impl Inner {
    /// Runs `f` in the engine's open transaction (begun at its first use).
    fn engine_tx<R>(&mut self, f: impl FnOnce(&mut Transaction<'_>, &mut super::Env<'_>) -> crate::types::Result<R>) -> Res<R> {
        let Inner { store, rng, open, now, holdings, caps, policy, mem, total, .. } = self;
        let mut t = match open.take() {
            Some(s) => store.resume(s, &mut **rng),
            None => store.transaction(&mut **rng)?,
        };
        let mut env = super::Env { now: *now, holdings, caps, policy, mem, total: *total };
        let r = f(&mut t, &mut env);
        *open = Some(t.suspend()?);
        // an abort of the engine's transaction counts the total again (`abort`)
        *total = env.total;
        r.map_err(to_store)
    }
}

impl osis_store::CipherHost for Inner {
    fn bears(&mut self, s: &osis_base::SyncId, key: &osis_crypto::VerifyingKey) -> Res<bool> {
        self.engine_tx(|t, _| super::path::bears(t, s, key))
    }

    fn held(&mut self, id: &BlobId) -> Res<bool> {
        let key = rows::engine_key(id);
        if self.read_in(true, |t, _| Ok(t.get_local(&key)?.is_some())).map_err(to_store)? {
            return Ok(true);
        }
        self.engine_tx(|t, _| Ok(t.get_local(&key)?.is_some()))
    }

    fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> Res<Option<Vec<u8>>> {
        if let Some(b) = self.read_in(true, |t, _| Ok(t.read_blob(id, offset, len)?)).map_err(to_store)? {
            return Ok(Some(b));
        }
        self.engine_tx(|t, _| Ok(t.read_blob(id, offset, len)?))
    }

    fn len(&mut self, id: &BlobId) -> Res<Option<u64>> {
        if let Some(n) = self.read_in(true, |t, _| Ok(t.blob_len(id)?)).map_err(to_store)? {
            return Ok(Some(n));
        }
        self.engine_tx(|t, _| Ok(t.blob_len(id)?))
    }

    /// Held in memory, the blob is the memory part's: no entry of the durable store names it.
    fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> Res<bool> {
        if self.held(id)? {
            return Ok(false);
        }
        let hold = |t: &mut Transaction<'_>, env: &mut super::Env<'_>| {
            if t.blob_len(id)?.is_none() {
                t.put_blob(id, blob)?;
            }
            t.put_local(&rows::engine_key(id), &[], Shred::No)?;
            bytes_arrived(t, env, id)
        };
        match memory {
            true => self.write_in(true, hold).map_err(to_store)?,
            false => self.engine_tx(hold)?,
        }
        Ok(true)
    }

    fn release(&mut self, id: &BlobId, memory: bool) -> Res<()> {
        let release = |t: &mut Transaction<'_>, env: &mut super::Env<'_>| {
            t.remove_local(&rows::engine_key(id), Shred::No)?;
            unref(t, env, id)
        };
        match memory {
            true => self.write_in(true, release).map_err(to_store),
            false => self.engine_tx(release),
        }
    }

    /// The engine forgot blob `id` with its commit: its own entries go under every sync ID, with
    /// no tombstone (an own entry logs a commit held here; held again, it is logged again).
    fn forgot(&mut self, id: &BlobId) -> Res<()> {
        let forgot = |t: &mut Transaction<'_>, env: &mut super::Env<'_>| {
            for s in super::entries::naming(t, id)? {
                if super::entries::get(t, &s, id)?.is_some_and(|r| r.own) {
                    super::entries::remove(t, env, &s, id, super::entries::Removal::Untombed)?;
                }
            }
            Ok(())
        };
        self.write_in(true, forgot).map_err(to_store)?;
        self.engine_tx(forgot)
    }

    /// The engine forgot blob `id`'s commit as never received (a release, lost access): its own
    /// tombstones end, so it is fetched again where present once needed (spec/sync-judgement.md
    /// §3 Dropped bodies). A verified Delete's tombstone stays.
    fn unreceived(&mut self, id: &BlobId) -> Res<()> {
        let unreceived = |t: &mut Transaction<'_>, env: &mut super::Env<'_>| {
            let tombed: Vec<osis_base::SyncId> = t.scan_local(&[rows::TOMB_BY_BLOB, &id.0].concat(), b"", usize::MAX)?.into_iter().filter_map(|(k, _)| k.get(k.len().saturating_sub(16)..).and_then(|x| x.try_into().ok()).map(osis_base::SyncId)).collect();
            for s in tombed {
                if super::entries::tombstone(t, &s, id)?.is_some_and(|x| !x.deleted) {
                    super::entries::lift(t, env, &s, id)?;
                }
            }
            Ok(())
        };
        self.write_in(true, unreceived).map_err(to_store)?;
        self.engine_tx(unreceived)
    }

    /// S is pulled anew from every source (`N/` marked as a raise is, over a mark of some sources
    /// only), so the bodies it lacks are fetched again (spec/sync-judgement.md §3 Dropped bodies).
    fn refetch(&mut self, s: &osis_base::SyncId) -> Res<()> {
        self.engine_tx(|t, env| {
            let mark = [rows::ANEW, &s.0].concat();
            if !super::Store::anew_everywhere(t, s)? {
                t.put_local(&mark, rows::ANEW_RAISED, Shred::No)?;
            }
            env.mem.anew.wrote_added(s, true, true);
            Ok(())
        })
    }

    fn local(&mut self, f: &mut dyn FnMut(&mut Transaction<'_>) -> Res<()>) -> Res<()> {
        self.engine_tx(|t, _| Ok(f(t)?))
    }

    fn commit(&mut self) -> Res<()> {
        let Inner { store, rng, open, .. } = self;
        let Some(s) = open.take() else { return Ok(()) };
        store.resume(s, &mut **rng).commit()
    }

    fn abort(&mut self) {
        // a suspended transaction dropped aborts; the total is counted again
        self.open = None;
        self.total = None;
        self.mem.stamps.wrote(&super::UNREAD_FIXED, true);
    }

    fn forensic_keys(&mut self) -> Res<Vec<[u8; 32]>> {
        self.commit()?;
        self.store.forensic_keys()
    }

    fn test_copy(&self, _clock: Arc<dyn osis_base::Clock>) -> Res<Inner> {
        Ok(Inner {
            store: self.store.test_copy()?,
            rng: self.rng.test_copy(),
            open: self.open.as_ref().map(osis_store::Suspended::test_copy),
            now: self.now,
            holdings: self.holdings.clone(),
            caps: self.caps.clone(),
            policy: self.policy.clone(),
            ram: self.ram.test_copy()?,
            mem: self.mem.clone(),
            total: self.total,
            past_cap: self.past_cap.clone(),
            unheld: self.unheld.clone(),
            room: self.room.clone(),
            room_fx: self.room_fx.clone(),
            room_gone: self.room_gone.clone(),
            room_conn: self.room_conn.clone(),
            clock: self.clock.clone(),
        })
    }
}
