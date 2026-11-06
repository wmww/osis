//! Inbox labels (spec/sync.md §3, §5): stamping handled blobs, clearing what waits for nothing, and
//! copying grants under the home label.

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
    /// deposited, for `clear_inbox`.
    pub(super) fn inbox_stampable(&mut self, l: &LabelId, id: &BlobId, c: &CommitId) -> Result<bool> {
        let latest = self.inbox_latest();
        if self.state.stamped_inbox_other(l, c, id) || self.inbox_opened(l, id)?.is_none_or(|o| o.until > latest) {
            return Ok(false);
        }
        if self.state.declined.contains(c) {
            return Ok(true);
        }
        let Some((m, o)) = self.inbox_valid(l, id, c)? else { return Ok(false) };
        let actors = self.inbox_actors(l);
        let on = self.inbox_about(&actors, c, &m, &o);
        Ok(o.ais.iter().any(|ai| m.header.aspects.get(*ai).is_some_and(|a| on.contains(&a.tid))))
    }

    /// An admin keeps at most `INBOX_WAITING` entries and bytes of them under an inbox label at a
    /// host waiting for nothing it can do (spec/sync.md §5): a deposit that is no commit of the
    /// label, past those it stamps or still judges. Over that, it deletes all but invite requests
    /// first, those expiring too far ahead before the rest, then the requests earliest to expire,
    /// so a stranger's fill ends with this pass, what does not open never costs a user an invite,
    /// and the rest of the budget stays free. A request goes only past `INBOX_WAITING` of them.
    pub(super) fn clear_inbox(&mut self, conn: ConnId, host: HostKey, p: &Head, out: &mut Vec<crate::sync::Action>) -> Result<()> {
        let (l, keys) = (p.l, &p.keys);
        if keys.delete.is_none() {
            return Ok(());
        }
        let deposited = self.state.deposited_at(&host, &l);
        if deposited.is_empty() || self.inbox_actors(&l).is_empty() {
            return Ok(());
        }
        let latest = self.inbox_latest();
        let mut waiting = Vec::new();
        for id in deposited {
            let Some(kind) = self.state.entries.get(&(l, id)).map(|e| e.kind.clone()) else { continue };
            let idle = match &kind {
                Kind::Commit { .. } | Kind::Parked(_) => false,
                Kind::Inbox(Some(c)) => {
                    let pending = self.engine.core.ix.pending.contains_key(c) && self.inbox_opened(&l, &id)?.is_some_and(|o| o.until <= latest);
                    !pending && !self.inbox_stampable(&l, &id, c)?
                }
                _ => true,
            };
            if !idle {
                continue;
            }
            let Some(blob) = self.engine.blob(&id)? else { continue };
            let until = osis_label::Prefix::parse(&blob).ok().and_then(|x| x.expiry()).map_or(u64::MAX, |w| w.0);
            let near = until <= latest;
            waiting.push((near && matches!(kind, Kind::Request(_)), near, until, id, blob.len()));
        }
        let over = |w: &[(bool, bool, u64, BlobId, usize)]| w.len() > osis_base::format::INBOX_WAITING || w.iter().map(|x| x.4).sum::<usize>() > osis_base::format::INBOX_WAITING_BYTES;
        if !over(&waiting) {
            return Ok(());
        }
        waiting.sort();
        waiting.reverse();
        let raw = self.raw_now();
        let mut items = Vec::new();
        while over(&waiting) {
            let Some((_, _, _, id, _)) = waiting.pop() else { break };
            let Some(c) = self.conns.get_mut(&conn) else { break };
            if crate::sync::in_flight(c, &c.req.deleting, (l, id), raw) {
                continue;
            }
            if let Some(item) = delete_item(keys, &l, id, None, None, &[], true) {
                c.req.deleting.insert((l, id), (raw, crate::sync::UNTAGGED));
                items.push(item);
            }
        }
        if !items.is_empty() {
            self.command(conn, Command::Delete { label: l, items }, out)?;
        }
        Ok(())
    }

    /// The things commit `c` (header in `m`) of opened inbox blob `o` is about for `actors`
    /// (spec/sync.md §3): where it has an edge or box of one of them or of an actor one owns,
    /// and, of a `label.0` write (it names no holder), the things the payload names that one of
    /// them holds an edge on, by the roster as applied here, not the payload's word.
    pub(super) fn inbox_about(&mut self, actors: &[Tid], c: &CommitId, m: &osis_engine::engine::Meta, o: &crate::sync::inbound::Opened) -> BTreeSet<Tid> {
        let named = self.engine.holders_named(c);
        let mine = |x: &Tid| self.engine.record_chain(x).any(|y| actors.contains(&y));
        let mut on: BTreeSet<Tid> = named.iter().filter(|(_, ms)| ms.iter().any(mine)).filter_map(|(ai, _)| m.header.aspects.get(*ai).map(|a| a.tid)).collect();
        for t in o.things.iter().map(|t| t.tid) {
            if m.header.aspects.iter().any(|a| a.tid == t && a.ak.as_str() == "label.0") && self.engine.roster(&t).keys().any(mine) {
                on.insert(t);
            }
        }
        on
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
    /// label `l` (spec/sync.md §3; the inbox may be another label, its first admin's: a group's holders
    /// learn its edges there, its inbox reaching only its admins): of a role commit, the carried
    /// parts on the things it writes an edge of `g` or an actor it is first admin of on, or boxes one on (boxes
    /// are sealed to the actor anyway), or, of a `label.0` write, its parts on the named things `g`
    /// or an actor it owns holds an edge on (a thing's first label, delivered to its holders), with
    /// the `label.0` and `created.0` commits of those things
    /// and their authors' chains (a granter who is no co-reader has placed none there), so the
    /// actor's other nodes and readers find the grant and its labels there; nothing from a blob
    /// expiring less than `INBOX_COPY_MIN_LEFT` from now (an expiry is the sender's word: a short
    /// one would free the deposit budget for the next copy), and not what an entry there already
    /// holds. Only an admin of `g` copies: a reader of an actor whose inbox is its own label reads
    /// the blob itself, and all of them copying would flood the label. The consumed inbox blob
    /// stays until it expires: its label hints are what a later holder that cannot apply the copied
    /// `label.0` yet opens the thing's label by.
    pub(super) fn inbox_certificates(&mut self, g: &Tid, l: LabelId) -> Result<BTreeMap<CommitId, Parts>> {
        let mut out: BTreeMap<CommitId, Parts> = BTreeMap::new();
        // only under the actor's home label (spec/sync.md §3): an inbox at another group's label
        // would show that group's readers the actor's edges, labels and box keys
        if self.engine.core.secret_actor(g) != Some(*g) || self.engine.role_on(g) != Some(Role::Admin) {
            return Ok(out);
        }
        // every inbox a blob about `g` may have come under (a sender knowing an older `keys.0` of
        // `g`, naming none, went up its record chain)
        let opened: Vec<(LabelId, BlobId, CommitId)> = self
            .engine
            .inbox_candidates(g)
            .into_iter()
            .flat_map(|li| self.state.of_kind(&li, Kind::TAG_INBOX).into_iter().map(move |b| (li, b)))
            .filter_map(|(li, b)| if let Some(Kind::Inbox(Some(c))) = self.state.entries.get(&(li, b)).map(|e| &e.kind) { Some((li, b, *c)) } else { None })
            .collect();
        let now = self.now();
        // what the last passes found all there (`InboxCopied`): a pass walks only what is new
        self.inbox_copied.lost(self.state.losses);
        for (li, b, c) in opened {
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
            let on = self.inbox_about(std::slice::from_ref(g), &c, &m, &o);
            let ais: BTreeSet<usize> = o.ais.iter().copied().filter(|ai| m.header.aspects.get(*ai).is_some_and(|a| on.contains(&a.tid))).collect();
            if ais.is_empty() {
                continue;
            }
            let mut copy = vec![(c, ais)];
            // labels only of those things the payload names (its list is the sender's word: it
            // could name any thing this node holds)
            for t in o.things.iter().map(|t| t.tid).filter(|t| on.contains(t)) {
                copy.extend(self.engine.aspect_commit(&t, "created.0"));
                // every `label.0` write: a later one (a rotation's new step) is a delta on the record
                // an earlier one set, useless alone. None of a thing the actor reads no more (a late
                // blob): its current steps are not for its readers, as a re-sent removal names none
                if self.engine.core.may_read(g, &t) {
                    copy.extend(self.engine.aspect_commits(&t, "label.0"));
                }
            }
            // all there already (another holder's copy counts), the usual case: a chain taken now
            // would carry what moved since. A thing's `label.0` arriving after the grant was
            // copied (its first label, or a later step) makes it not so
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
                    let mut on: BTreeSet<Tid> = self.engine.holders_named(&c).values().flat_map(|ms| ms.iter().copied()).collect();
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
                for (y, q) in self.chain_under(&x, &parts).unwrap_or_default() {
                    out.entry(y).or_default().extend(q);
                }
                out.entry(x).or_default().extend(parts);
            }
        }
        Ok(out)
    }
}
