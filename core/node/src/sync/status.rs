//! What the API, tests and the simulator read of the engine.

use super::*;

impl SyncEngine {
    /// Where each synced label stands (the API's status): per label its group, its sources (nodes
    /// connected now with it open, whoever dialed) and how many of them this node's pass is done
    /// with, whether every host failed it (stranded), which connected hosts refuse it, and when it
    /// last had every source caught up.
    pub fn label_status(&mut self) -> Vec<LabelStatus> {
        let now = self.raw_now();
        let mut out = Vec::new();
        for (g, l) in self.labels() {
            let leaving = self.leaving().any(|a| *a == self.engine.group_actor(&g));
            let mut failed = BTreeSet::new();
            let mut dialed = BTreeSet::new();
            let passed = self.state.passed.contains(&l.id);
            let mut st = LabelStatus { group: g, label: l.id, hosts: l.hosts.len(), sources: 0, idle: 0, opening: 0, stranded: false, refused_by: Vec::new(), leaving, last_sync: None, passed, replaced: l.replaced };
            for c in self.conns.values() {
                let host = l.hosts.iter().find(|a| a.key == c.host);
                if let Some(a) = host.filter(|_| c.up && c.req.refusals.get(&l.id).is_some_and(|(_, code)| *code == Code::NOT_ADMITTED)) {
                    st.refused_by.push(a.clone());
                }
                let Some(x) = c.labels.get(&l.id) else {
                    // labels are started once the session is ready
                    st.opening += usize::from(c.up && !c.session.is_ready() && (host.is_some() || c.peer));
                    continue;
                };
                if x.phase == Phase::Failed && host.is_some() {
                    failed.insert(c.host);
                }
                st.opening += usize::from(c.up && x.phase == Phase::Opening && (host.is_some() || c.peer));
                // a host the label no longer names is on its way out: no source of it
                if c.up && x.phase == Phase::Open && !x.receipts && (host.is_some() || c.peer) {
                    dialed.insert(c.host);
                    st.sources += 1;
                    if x.idle() && c.session.outstanding() == 0 {
                        st.idle += 1;
                    }
                }
            }
            // a served session is its own source (not caught up: no pass of this node runs on it)
            // unless it proved it is a node this node has a connection to; only a valid proof
            // names one, so no session can make this count smaller for a node it is not
            st.sources += self.served.values().filter(|s| s.opens(&l.id) && s.named().is_none_or(|k| !dialed.contains(&k))).count();
            st.stranded = !l.hosts.is_empty() && l.hosts.iter().all(|a| failed.contains(&a.key));
            if !st.stranded && st.sources > 0 && st.idle == st.sources {
                self.last_synced.insert(l.id, now);
            }
            st.last_sync = self.last_synced.get(&l.id).copied();
            out.push(st);
        }
        self.last_synced.retain(|l, _| out.iter().any(|s| s.label == *l));
        out
    }

    /// Whether a host answered that the head of `l` does not list this node's static entry and
    /// every other route of `l` failed too: the key actor is no reader there, for a link's key one
    /// it no longer holds K (spec/sync.md §5, spec/permissions.md §7). A route not answering (not
    /// connected yet, or down) says nothing: one host's word is no end while another may serve it.
    pub fn static_entry_refused(&mut self, l: &LabelId) -> bool {
        let routes = self.wanted_labels().into_iter().find(|(_, x, _)| x == l).map_or(Vec::new(), |(_, _, r)| r);
        let on: Vec<&LConn> = self.conns.values().filter_map(|c| c.labels.get(l)).collect();
        let failed = |h: &state::HostKey| self.conns.values().any(|c| c.host == *h && c.labels.get(l).is_some_and(|x| x.phase == Phase::Failed));
        routes.iter().all(failed) && on.iter().all(|x| x.phase == Phase::Failed) && on.iter().any(|x| x.static_refused)
    }

    /// Sync connections up, whichever side dialed: a client's session is none.
    pub fn connected(&self) -> usize {
        self.conns.values().filter(|c| c.up).count() + self.served.values().filter(|s| s.syncing()).count()
    }

    /// The addresses `g` syncs with as this node knows them: its live labels' hosts, then the
    /// co-readers it dials for them (`reach.0`, a link's sharer), each by its lasting `peer://`
    /// address: a read leaves the LAN routes (`peer_addresses` expires them) alone.
    pub fn group_peers(&mut self, g: &Tid) -> Vec<Address> {
        let ids: BTreeSet<LabelId> = self.labels().iter().filter(|(x, l)| x == g && !l.replaced).map(|(_, l)| l.id).collect();
        let mut out: Vec<Address> = self.labels().iter().filter(|(x, l)| x == g && !l.replaced).flat_map(|(_, l)| l.hosts.clone()).collect();
        if self.cfg.peers {
            let co_readers: Vec<Address> = self.peers().iter().filter(|(_, p)| !p.labels.is_disjoint(&ids)).map(|(k, p)| Address { url: osis_transport::peer_url(&p.reach.items), key: *k }).collect();
            out.extend(co_readers);
            out.extend(self.link_routes().into_values().filter(|(_, ls)| !ls.is_disjoint(&ids)).map(|(a, _)| a));
        }
        let mut seen = BTreeSet::new();
        out.retain(|a| seen.insert(a.key));
        out
    }

    /// Inbox blobs (grants, notices) not yet sent, sent to nowhere (no node to take them), or
    /// not yet answered by a host (the outbox and the delivery records are stored and restored
    /// at open).
    pub fn deliveries_pending(&self) -> usize {
        self.outbox.len() + self.state.sent_inbox.values().filter(|s| s.unsent()).count()
    }

    /// What each pending delivery (`deliveries_pending`) is about, for `wait_synced`'s scope:
    /// an inbox delivery's things (a grant's target), a non-writer's deposit its label's group;
    /// empty when none is known (an inbox blob outside a delivery record).
    pub fn pending_about(&mut self) -> Vec<Vec<Tid>> {
        let unsent = self.state.sent_inbox.values().filter(|s| s.unsent()).map(|s| s.things.clone());
        let mut out: Vec<Vec<Tid>> = unsent.collect();
        let queued: Vec<(LabelId, Option<(Tid, osis_base::CommitId)>)> = self.outbox.keys().map(|k| (k.1, self.state.outbox.get(k).and_then(|o| o.delivery))).collect();
        for (l, d) in queued {
            out.push(match d {
                Some(k) => self.state.sent_inbox.get(&k).map(|s| s.things.clone()).unwrap_or_default(),
                None => self.group_of(&l, None).into_iter().collect(),
            });
        }
        out
    }

    /// A digest of this node's sync state (simulator comparisons): what commits and parts its
    /// entries, presence, deposits and blob records name, certificates, carriers, and
    /// what the store holds.
    pub fn state_digest(&mut self) -> [u8; 32] {
        let s = &self.state;
        // a blob by what it carries: its ID, wrap, salt and stamp are the luck of when its sealing
        // drew from the random stream, so two runs doing the same in another order differ there
        let name = |l: Option<&LabelId>, b: &osis_base::BlobId| {
            let kind = l.and_then(|l| s.entries.get(&(*l, *b))).map(|e| &e.kind);
            match (kind, s.blobs.get(b)) {
                (Some(state::Kind::Commit { commit, parts, .. }), _) => format!("{commit:?}{parts:?}"),
                (Some(k), _) => format!("{k:?}"),
                (None, Some(r)) => format!("{:?}{:?}", r.commit, r.parts),
                (None, None) => String::new(),
            }
        };
        // and by what, not where: two copies of a commit under a label are settled by the lower ID,
        // so which holder's copy stays, under which label, is that luck too
        let mut lines = BTreeSet::new();
        for (l, b) in s.entries.keys() {
            lines.insert(format!("e{}", name(Some(l), b)));
        }
        let sets = [("p", &s.present), ("d", &s.deposited)];
        for (k, set) in sets {
            for (host, l, b) in set {
                lines.insert(format!("{k}{host:?}{}", name(Some(l), b)));
            }
        }
        for (_, c) in &s.certs {
            lines.insert(format!("k{c:?}"));
        }
        for (c, x) in &s.carriers {
            lines.insert(format!("s{c:?}{:?}", x.by));
        }
        for id in s.blobs.keys() {
            lines.insert(format!("b{}", name(None, id)));
        }
        let ids: BTreeSet<(Option<LabelId>, osis_base::BlobId)> = s.entries.keys().map(|(l, b)| (Some(*l), *b)).chain(s.blobs.keys().map(|b| (None, *b))).collect();
        for (l, b) in ids {
            lines.insert(format!("h{}{}", name(l.as_ref(), &b), self.engine.has_blob(&b)));
        }
        let mut h = osis_base::hash::Hasher::new();
        for x in lines {
            h.update(x.as_bytes());
        }
        h.finalize()
    }

    /// What passes did so far (scale checks).
    pub fn pass_stats(&self) -> PassStats {
        PassStats { examined: self.engine.examined(), ..self.stats }
    }

    /// The most any label's work set holds waiting for its pass (`SyncConfig::work_max`).
    pub fn work_waiting(&self) -> usize {
        self.conns.values().flat_map(|c| c.labels.values().map(|l| &l.work)).chain(self.local_work.iter().map(|x| x.1)).map(|w| w.touched.size()).max().unwrap_or(0)
    }

    /// Whether every open label on every connection has completed a pass and nothing is
    /// outstanding (tests, simulator quiescence).
    pub fn is_idle(&self) -> bool {
        self.conns.values().all(|c| c.session.outstanding() == 0 && c.labels.values().all(|l| l.receipts || l.phase != Phase::Open || l.idle()))
    }

    /// A one-line summary of each label on each connection (tests, diagnostics).
    pub fn describe(&self) -> Vec<String> {
        let mut v = Vec::new();
        for (id, c) in &self.conns {
            for (l, x) in &c.labels {
                v.push(format!(
                    "conn {id} {l:?}: {:?} synced {} syncing {} dirty {} registering {} writer {} reader {} outstanding {} head {:?}",
                    x.phase,
                    x.synced,
                    x.syncing,
                    x.dirty,
                    x.registering.is_some(),
                    x.keys.is_writer(),
                    x.keys.epochs[0].is_some(),
                    c.session.outstanding(),
                    x.head.as_ref().map(|h| h.id().0[0])
                ));
            }
        }
        v
    }

    /// How long (ms) a dial to `key` still waits for its retry pause, if it waits (tests).
    #[doc(hidden)]
    pub fn retrying(&self, key: &[u8; 32]) -> Option<u64> {
        self.retry.get(key).map(|(_, t)| t.saturating_sub(self.raw_now()))
    }

    /// Diagnostics since the last call (tests).
    pub fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diagnostics)
    }

    /// Whether a stranded heartbeat went under a label (tests).
    pub fn stranded_at(&self, l: &LabelId) -> bool {
        self.state.stranded.contains_key(l)
    }

    /// Entries this node knows under a label (tests).
    pub fn entries(&self, l: &LabelId) -> Vec<(osis_base::BlobId, EntryKind)> {
        self.state.label_entries(l).map(|(b, e)| (b, e.kind.clone())).collect()
    }

    /// The groups label `l` is held under on this node's connections (tests).
    #[doc(hidden)]
    pub fn conn_groups(&self, l: &LabelId) -> Vec<osis_base::Tid> {
        self.conns.values().filter_map(|c| c.labels.get(l)).map(|x| x.group).collect()
    }

    /// The wrap and stamp this node keeps for an entry (tests).
    #[doc(hidden)]
    pub fn entry_meta(&self, l: &LabelId, b: &osis_base::BlobId) -> Option<([u8; osis_crypto::WRAP_LEN], Option<osis_crypto::Signature>)> {
        self.state.entries.get(&(*l, *b)).map(|e| (e.wrap, e.stamp))
    }

    /// Sync records stored under `y/<tag>` (tests: growth after a lifecycle).
    #[doc(hidden)]
    pub fn sync_rows(&mut self, tag: u8) -> usize {
        let _ = self.state.flush(&mut self.engine);
        let mut n = 0;
        let _ = self.engine.run(|tx| {
            tx.scan(&[b'y', b'/', tag], |_, _| {
                n += 1;
                Ok(())
            })
        });
        n
    }

    /// Whether this node still holds a commit blob's key or ciphertext (tests: a dropped body
    /// leaves neither).
    pub fn holds_blob(&mut self, b: &osis_base::BlobId) -> bool {
        self.state.blobs.contains_key(b) || self.engine.has_blob(b)
    }
}
