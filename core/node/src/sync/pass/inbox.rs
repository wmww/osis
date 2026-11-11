//! Inbox labels (spec/sync.md §3, §5): stamping handled blobs and copying grants under the home
//! label.

use super::*;

/// The least lifetime an inbox blob must have left for its grant to be copied under the home
/// label (`inbox_certificates`, spec/sync.md §3): the copy outlives the blob, so a sender's short
/// expiry would free its deposit budget for the next copy at once. At 0 a stranger with the
/// deposit seed stores grants without bound; at `INBOX_LIFETIME` no node ever copies. Past it a
/// node opening a late blob applies the grant without copying: unless another node copied it
/// earlier, the actor's later nodes never find it (the node's writes count as acting, so the
/// sender does not re-send). No rule on the blob alone avoids a number: a late genuine blob and a
/// stranger's short-lived one look alike (both expiry and `ts` are the sender's word).
const INBOX_COPY_MIN_LEFT: u64 = osis_base::format::INBOX_LIFETIME_MS / 2;

impl SyncEngine {
    /// A writer stamps in place the inbox blobs handled here (spec/sync.md §5; `inbox_stampable`).
    /// Each leaves the deposit budget and stays readable for the actor's other nodes until it
    /// expires.
    pub(super) fn stamp_inbox(&mut self, conn: ConnId, host: HostKey, l: LabelId, write: &osis_crypto::SigningSecret, uploads: &mut Vec<osis_proto::Entry>) -> Result<()> {
        for (id, e) in self.due_entries(conn, host, l) {
            let Kind::Inbox(Some(c)) = e.kind else { continue };
            if !self.inbox_stampable(&l, &id, &c)? {
                continue;
            }
            let Some(blob) = self.engine.blob(&id)? else { continue };
            uploads.push(self.stamped_upload(l, id, e, blob, write));
        }
        Ok(())
    }

    /// The latest prefix expiry an honest sender's inbox blob can carry (spec/sync.md §3).
    pub(super) fn inbox_latest(&self) -> u64 {
        self.now().saturating_add(osis_base::format::INBOX_LIFETIME_MS + 2 * osis_base::format::MAX_DRIFT_MS)
    }

    /// Whether inbox blob `id` of commit `c` is one a writer stamps: a valid applied commit about
    /// an actor whose inbox this is, with parts a copy would take for it, or one this node's user
    /// declined; only the first blob of a commit under the label, and none expiring later than
    /// an honest sender's could (an expiry is the sender's word, and a stamp keeps the blob until
    /// then). A stranger can seal any commit he holds in any number of blobs: those stay
    /// deposited, for `clear_deposits`.
    pub(super) fn inbox_stampable(&mut self, l: &LabelId, id: &BlobId, c: &CommitId) -> Result<bool> {
        let latest = self.inbox_latest();
        if self.state.stamped_inbox_other(l, c, id) || self.inbox_opened(l, id)?.is_none_or(|o| o.until > latest) {
            return Ok(false);
        }
        if self.state.declined.contains(c) {
            return Ok(true);
        }
        let Some((m, o)) = self.inbox_valid(l, id, c)? else { return Ok(false) };
        let actors = self.inbox_actors_at(l);
        let on = self.inbox_about(&actors, c, &m);
        Ok(o.ais.iter().any(|ai| m.header.aspects.get(*ai).is_some_and(|a| on.contains(&a.tid))))
    }

    /// The things commit `c` (header in `m`) of an opened inbox blob is about for `actors`
    /// (spec/sync.md §3): where it has an edge or box of one of them.
    pub(super) fn inbox_about(&mut self, actors: &[Tid], c: &CommitId, m: &osis_engine::engine::Meta) -> BTreeSet<Tid> {
        let named = self.engine.holders_named(c);
        named.iter().filter(|(_, ms)| ms.iter().any(|x| actors.contains(x))).filter_map(|(ai, _)| m.header.aspects.get(*ai).map(|a| a.tid)).collect()
    }

    /// Commit `c` of opened inbox blob `b` under `l`, applied here and valid in every part the
    /// blob carries, with what the blob opened to.
    pub(super) fn inbox_valid(&mut self, l: &LabelId, b: &BlobId, c: &CommitId) -> Result<Option<(osis_engine::engine::Meta, std::sync::Arc<crate::sync::inbound::Opened>)>> {
        if self.engine.core.ix.pending.contains_key(c) {
            return Ok(None);
        }
        let Some(m) = self.engine.core.ix.commits.get(c).cloned() else { return Ok(None) };
        let Some(o) = self.inbox_opened(l, b)? else { return Ok(None) };
        Ok(o.ais.iter().all(|ai| m.valid.get(*ai).copied().unwrap_or(false)).then_some((m, o)))
    }

    /// What a grantee node copies of what `g`'s inbox brought, once applied, under `g`'s home
    /// label `l` (spec/sync.md §3): of a role commit, the carried parts on the things it writes
    /// an edge of `g` on, or boxes it on, with the `label.0` and `created.0` commits of those
    /// things and their authors' chains (a granter who is no co-reader has placed none there), so
    /// the actor's other nodes and readers find the grant and its labels there; nothing from a
    /// blob expiring less than `INBOX_COPY_MIN_LEFT` from now (an expiry is the sender's word: a
    /// short one would free the deposit budget for the next copy), and not what an entry there
    /// already holds. Only an admin of `g` copies: a reader of an actor reads the blob itself, and
    /// all of them copying would flood the label. The consumed inbox blob stays until it expires:
    /// its label hints are what a later holder that cannot apply the copied `label.0` yet opens
    /// the thing's label by.
    pub(super) fn inbox_certificates(&mut self, g: &Tid, l: LabelId) -> Result<crate::labeling::Certs> {
        let mut out = crate::labeling::Certs::default();
        if self.engine.role_on(g) != Some(Role::Admin) {
            return Ok(out);
        }
        // an account's inbox is its D's home label, and what it brings is about the account
        let actor = self.engine.core.home_owner(g);
        let Some(li) = self.engine.inbox(&actor) else { return Ok(out) };
        let opened: Vec<(BlobId, CommitId)> = self
            .state
            .of_kind(&li, Kind::TAG_INBOX)
            .into_iter()
            .filter_map(|b| if let Some(Kind::Inbox(Some(c))) = self.state.entries.get(&(li, b)).map(|e| &e.kind) { Some((b, *c)) } else { None })
            .collect();
        let now = self.now();
        // what the last passes found all there (`InboxCopied`): a pass walks only what is new
        self.inbox_copied.lost(self.state.losses);
        let mut hosts = self.counted_at(g, l);
        if let Some(hs) = hosts.as_mut() {
            hs.sort();
            hs.dedup();
        }
        let epoch = self.engine.epochs(g).and_then(|e| osis_keys::wrap_epoch(&e.read));
        self.inbox_copied.counted(l, crate::sync::work::InboxAt { hosts, epoch });
        for (b, c) in opened {
            let copied = self.inbox_copied.has(&l, &b);
            #[cfg(not(debug_assertions))]
            if copied {
                continue;
            }
            let Some((m, o)) = self.inbox_valid(&li, &b, &c)? else { continue };
            if o.until < now.saturating_add(INBOX_COPY_MIN_LEFT) {
                continue;
            }
            // the carried parts on the things the commit has an edge or box of the actor on (the
            // payload carries the sender's choice of parts; a role commit's are all
            // role-class)
            let on = self.inbox_about(std::slice::from_ref(&actor), &c, &m);
            let ais: BTreeSet<usize> = o.ais.iter().copied().filter(|ai| m.header.aspects.get(*ai).is_some_and(|a| on.contains(&a.tid))).collect();
            if ais.is_empty() {
                continue;
            }
            let mut copy = vec![(c, ais)];
            // labels only of those things the payload names (its list is the sender's word: it
            // could name any thing this node holds)
            for t in o.things.iter().map(|t| t.tid).filter(|t| on.contains(t)) {
                // its record travels raw (`place_records`)
                out.records.insert(t);
                // every `label.0` write: a later one (a rotation's new step) is a delta on the record
                // an earlier one set, useless alone. None of a thing the actor reads no more (a late
                // blob): its current steps are not for its readers, as a re-sent removal names none
                if self.engine.core.may_read(&actor, &t) {
                    copy.extend(self.engine.aspect_commits(&t, "label.0"));
                }
            }
            // all there already (another holder's copy counts), the usual case: a chain taken now
            // would carry what moved since. A thing's `label.0` arriving after the grant was
            // copied (a later step) makes it not so
            let mut held = true;
            for (x, xs) in &copy {
                if !self.held_whole(g, l, x, xs)? {
                    held = false;
                    break;
                }
            }
            if held {
                if !copied {
                    // what moves the answer: an edge, record or label on these, or their holders
                    let holders: BTreeSet<Tid> = self.engine.holders_named(&c).values().flat_map(|ms| ms.iter().copied()).collect();
                    let mut on = holders;
                    on.extend(o.things.iter().map(|t| t.tid));
                    for (x, _) in &copy {
                        on.extend(self.engine.header(x).iter().flat_map(|h| h.aspects.iter().map(|a| a.tid).collect::<Vec<_>>()));
                    }
                    self.inbox_copied.add(l, b, on);
                }
                continue;
            }
            debug_assert!(!copied, "inbox_certificates skipped blob {b:?} that wants a copy");
            for (x, xs) in copy {
                let Some(h) = self.engine.header(&x) else { continue };
                let parts = parts_of(&h, |i| xs.contains(&i));
                out.extend(self.chain_under(&x, &parts).unwrap_or_default());
                out.commits.entry(x).or_default().extend(parts);
            }
        }
        Ok(out)
    }
}
