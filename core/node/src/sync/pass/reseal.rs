//! Re-seals decided at the end of a complete pass of an actor's labels (spec/permissions.md §3):
//! holders seen without a box at a current epoch, holders reported stranded (§4, `reports`),
//! plain things given secrets of their own, and the account's signing chain.

use super::*;

impl SyncEngine {
    /// Re-seals decided at the end of a complete pass of the actor's labels (spec/permissions.md
    /// §3): holders reported stranded (§4: a Stranded message or notice, `stranded_asks`), then
    /// holders seen without a box at a current epoch (`Engine::reseal_due`); delivered by inbox
    /// and placed under the actor's labels like any role commit.
    pub(super) fn reseal(&mut self, g: &Tid, l: LabelId) -> Result<()> {
        let Some(a) = self.engine.core.secret_actor(g) else { return Ok(()) };
        if self.engine.core.is_key_actor(&a) {
            return Ok(());
        }
        if !self.complete_pass(&a) {
            // the wait for peers ending may be all it lacks
            if !self.peers_waited(&a) {
                self.settle_by(self.peer_wait_end(&a), l);
            }
            return Ok(());
        }
        // the complete pass was checked just above
        struct Passed;
        impl crate::flows::SyncState for Passed {
            fn complete_pass(&self, _: &Tid) -> bool {
                true
            }
        }
        // plain things under `a` with holders: secrets of their own again, each left to the
        // author of the newest role write on it for `SETTLE_MS` after it came (it gives them
        // with its write, as a grant does): every admin giving them at once forks the thing's
        // secrets and labels, one each (spec/crypto.md §4)
        for t in self.engine.own_secrets_candidates(&a) {
            if let Some(at) = self.own_secrets_wait(&t) {
                self.settle_by(at, l);
                continue;
            }
            match self.engine.give_own_secrets_again(&t) {
                Ok(done) => self.take_done(done)?,
                Err(e) => self.diag(format!("secrets of its own for {t}: {e}")),
            }
        }
        // holders reported stranded, before the boxes `reseal_due` adds, which would box a
        // stranded holder lacking one twice; once per holder at the actor's current epochs
        for holder in self.stranded_asks.remove(&a).unwrap_or_default() {
            let epochs = self.engine.epochs(&a).map(|e| e.read.current()).unwrap_or_default();
            if self.resealed.get(&(a, holder)) == Some(&epochs) {
                continue;
            }
            // a holder the reporter names is checked here: only a current holder this node may
            // re-seal is
            match self.engine.reshare(&a, &holder) {
                Ok(done) => {
                    self.resealed.insert((a, holder), epochs);
                    self.take_done(done)?;
                }
                Err(e) => self.diag(format!("re-seal of stranded {holder} on {a}: {e}")),
            }
        }
        match self.engine.reseal_due(&a, &Passed) {
            Ok(done) => self.take_done(done)?,
            Err(e) => self.diag(format!("re-seal of {a}: {e}")),
        }
        // the account's signing chain, once its devices actor's labels are heard out
        if self.engine.core.account_devices().is_some_and(|(_, d)| d == a) {
            match self.engine.signing_due() {
                Ok(done) => self.take_done(done)?,
                Err(e) => self.diag(format!("rotation of the account: {e}")),
            }
        }
        Ok(())
    }

    /// Until when (raw ms) giving `t` secrets of its own again is left to another node: the
    /// author of the newest role write on `t` held, received less than `SETTLE_MS` ago.
    fn own_secrets_wait(&self, t: &Tid) -> Option<u64> {
        let roles = Ak::new(osis_schema::RawKey::ak(&ct::ROLES)).ok()?;
        let (_, c) = self.engine.core.ix.by_aspect.get(&(*t, roles))?.iter().next_back()?;
        let m = self.engine.core.ix.commits.get(c).filter(|m| m.origin != crate::events::Origin::Local)?;
        let (now, due) = (self.now(), m.received.0.saturating_add(SETTLE_MS));
        (due > now).then(|| self.raw_now().saturating_add(due - now))
    }
}
