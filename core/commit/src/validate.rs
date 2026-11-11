//! Structural validation of a resolved header (spec/wire.md §4, spec/commits.md §2, §5, §6).

use crate::cbor::strictly_ascending;
use crate::header::{FOREVER, Header, Kind, aspect_key, key_value, purge_value};
use crate::retention::{CREATED, EPHEMERAL_RETENTION, RELEASED, RETENTION, delete_levels, fixed_retention, release_expires};
use crate::Error;
use osis_base::format::{DELETE_AUTHOR, FORMAT_VERSION};
use osis_schema::PurgeBy;
use osis_schema::core_types::is_role_class;

impl Header {
    /// Checks every layout rule and every rule of spec/commits.md §2 a header shows: sort orders,
    /// indices, ranges, kinds and aspect classes, fixed retention, expiry, purge, frontier,
    /// delete levels. Linked lists must be resolved first.
    pub fn validate(&self) -> Result<(), Error> {
        if !self.is_resolved() {
            return Err(Error::Missing);
        }
        if self.version != FORMAT_VERSION {
            return Err(Error::Malformed("format version"));
        }
        let ord = |ok: bool, what: &'static str| if ok { Ok(()) } else { Err(Error::Malformed(what)) };
        ord(!self.aspects.is_empty(), "no aspects")?;
        ord(strictly_ascending(&self.aspects, |a| aspect_key(&a.tid, &a.ak)), "aspects not sorted and distinct")?;
        ord(strictly_ascending(&self.chunks, |c| c.blob), "chunks not sorted and distinct")?;
        ord(strictly_ascending(&self.purge, |p| osis_base::encode(&purge_value(p))), "purge not sorted and distinct")?;
        ord(strictly_ascending(&self.keys, |t| osis_base::encode(&key_value(t))), "delete keys not sorted and distinct")?;

        let kind = self.kind;
        use crate::header::Form;
        // session form belongs to content commits: role writes are commit form, so no later commit
        // can void them, and a snapshot has no own writes (spec/commits.md §3)
        if matches!(self.form, Form::Session(_)) && kind != Kind::Content {
            return Err(Error::Invalid("session form outside a content commit"));
        }
        // edge writes are judged by the timeline, which never asks whom the author acts for
        // (spec/permissions.md §5.2)
        if kind == Kind::Role && self.actor != self.author {
            return Err(Error::Invalid("role commit acting for another actor"));
        }
        let wall = self.ts.wall_ms().0;
        let mut used = vec![false; self.keys.len()];
        for a in &self.aspects {
            let ak = a.ak.as_str();
            // indices and ranges
            ord(a.lo <= FOREVER && a.hi <= FOREVER, "integer above 2^63 - 1")?;
            ord(strictly_ascending(&a.keys, |i| *i), "aspect delete keys not ascending")?;
            let mut levels = Vec::with_capacity(a.keys.len());
            for i in &a.keys {
                let tok = self.keys.get(*i).ok_or(Error::Malformed("delete key index out of range"))?;
                if let Some(u) = used.get_mut(*i) {
                    *u = true;
                }
                levels.push(tok.level);
            }
            if kind.has_own_writes() {
                ord(1 <= a.lo && a.lo < a.hi, "counter range")?;
            } else {
                ord(a.lo == 0 && a.hi == 0, "counter range of a commit without own writes")?;
            }
            // kinds and aspect classes
            if ak != CREATED && is_role_class(ak) != kind.is_role() {
                return Err(Error::Invalid("aspect of the wrong class for the commit kind"));
            }
            // a thing's record is its own commit's one minting, never a snapshot's; never
            // ephemeral (spec/commits.md §2)
            if ak == CREATED && (!kind.has_own_writes() || self.ephemeral.is_some()) {
                return Err(Error::Invalid("created.0 in a commit without own writes or an ephemeral one"));
            }
            // kept forever and judged by its own deltas (spec/commits.md §5): never snapshotted
            if ak == RETENTION && !kind.has_own_writes() {
                return Err(Error::Invalid("retention^.0 in a commit without own writes"));
            }
            // the role timeline walks every edge write (spec/commits.md §2)
            if kind == Kind::RoleSnapshot && ak == "roles.0" {
                return Err(Error::Invalid("compaction snapshot of roles.0"));
            }
            if let Some(f) = fixed_retention(ak) {
                ord(a.retention == f, "retention of a fixed-retention aspect")?;
            } else if let Err(m) = crate::retention::allowed(ak, &a.retention) {
                return Err(Error::Invalid(m));
            } else if kind == Kind::ContentSnapshot && a.retention.by != PurgeBy::Writer {
                return Err(Error::Invalid("compaction-snapshot delta not purgeable by writer"));
            }
            // levels as listed (ascending, since keys sort by level first): exactly those the
            // retention calls for
            if levels != delete_levels(&a.retention) {
                return Err(Error::Invalid("delete levels do not match the retention"));
            }
        }
        // a release request: durable content, `released.0` deltas alone, no purge field, expiring
        // `ROLE_KEEP` after its `ts` (spec/commits.md §5 Ending)
        if self.is_release() {
            let only = self.aspects.iter().all(|a| a.ak.as_str() == RELEASED);
            if kind != Kind::Content || self.ephemeral.is_some() || !only || !self.purge.is_empty() || self.expires != Some(release_expires(self.ts)) {
                return Err(Error::Invalid("released.0 outside a release request"));
            }
        }
        // expiry: one per commit, on deltas that may expire (spec/commits.md §6)
        if let Some(t) = self.expires {
            ord(t <= FOREVER, "integer above 2^63 - 1")?;
            if kind.is_role() {
                return Err(Error::Invalid("expires on a role commit"));
            }
            if self.aspects.iter().any(|a| a.ak.as_str() != RELEASED && fixed_retention(a.ak.as_str()).is_some()) {
                return Err(Error::Invalid("expires on a commit with a fixed-retention aspect"));
            }
            if t <= wall {
                return Err(Error::Invalid("expires not after the commit's ts"));
            }
        }
        // one author chain: at most one level-2 key (header-list blobs commit to it alone)
        if self.keys.iter().filter(|k| k.level == DELETE_AUTHOR).count() > 1 {
            return Err(Error::Invalid("more than one level-2 delete key"));
        }
        if used.iter().any(|u| !u) {
            return Err(Error::Malformed("delete key no aspect calls for"));
        }
        for c in &self.chunks {
            ord(strictly_ascending(&c.keys, |i| *i), "chunk delete keys not ascending")?;
            if c.keys.iter().any(|i| *i >= self.keys.len()) {
                return Err(Error::Malformed("chunk delete key index out of range"));
            }
        }
        if !self.purge.is_empty() {
            if kind.is_role() {
                return Err(Error::Invalid("purge request on a role commit"));
            }
            if self.purge.iter().any(|p| is_role_class(p.ak().as_str())) {
                return Err(Error::Invalid("purge request naming role-class deltas"));
            }
            if self.purge.iter().filter(|p| matches!(p, crate::header::PurgeItem::Author { .. })).count() > osis_base::format::MAX_AUTHOR_ITEMS {
                return Err(Error::Invalid("too many purge items by author"));
            }
        }
        if self.frontier.is_some() && kind != Kind::Role {
            return Err(Error::Invalid("frontier outside a role commit"));
        }
        // a rotation of an account's signing chain: on a role commit signed at an epoch it
        // supersedes, its lists ascending and distinct (spec/wire.md §4 field 16)
        if let Some(r) = &self.rotation {
            if kind != Kind::Role {
                return Err(Error::Invalid("rotation outside a role commit"));
            }
            ord(strictly_ascending(&r.supersedes, |c| *c) && strictly_ascending(&r.names, |c| *c), "rotation lists not sorted and distinct")?;
            if !self.epoch.is_some_and(|e| r.supersedes.contains(&e)) {
                return Err(Error::Invalid("rotation not superseding the epoch it is signed at"));
            }
            if self.actor != self.author || !self.aspects.iter().any(|a| a.tid == self.author && a.ak.as_str() == "keys.0") {
                return Err(Error::Invalid("rotation not writing its author's keys.0 as its author"));
            }
        }
        // an ephemeral commit is a content commit or a content snapshot (each in its form, as a
        // durable one) and carries nothing a stored commit is for (spec/commits.md §2, §3)
        if let Some(c) = self.ephemeral {
            if !matches!(kind, Kind::Content | Kind::ContentSnapshot) {
                return Err(Error::Invalid("ephemeral commit neither a content commit nor a content snapshot"));
            }
            if !self.chunks.is_empty() || !self.purge.is_empty() || self.links != crate::header::Links::default() {
                return Err(Error::Invalid("ephemeral commit with chunks, a purge or linked lists"));
            }
            if self.aspects.iter().any(|a| a.retention != EPHEMERAL_RETENTION) {
                return Err(Error::Invalid("ephemeral commit with a retention other than writer"));
            }
            if c != crate::header::EphClass::Plain && (self.expires.is_some() || self.undoes.is_some()) {
                return Err(Error::Invalid("relay-only commit with an expiry or an undo"));
            }
        }
        Ok(())
    }
}
