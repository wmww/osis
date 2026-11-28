//! Structural validation of a resolved header (spec/wire.md §4, spec/commits.md §2, §5, §6).

use crate::cbor::strictly_ascending;
use crate::header::{AspectEntry, EphClass, FOREVER, Form, Header, Kind, Links, ListField, PIECED, PurgeItem, aspect_order, purge_bytes};
use crate::path::{Path, Paths};
use osis_base::format::DELETE_AUTHOR;
use crate::retention::{CREATED, EPHEMERAL_PURGE_BY, delete_levels, fixed_purge_by};
use crate::Error;
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
        let ord = |ok: bool, what: &'static str| if ok { Ok(()) } else { Err(Error::Malformed(what)) };
        ord(!self.aspects.is_empty(), "no aspects")?;
        // aspects sorted and distinct; an aspect in pieces (`secrets.0` alone) is consecutive
        // entries sharing every field but the hash, ascending by it (spec/wire.md §4 Pieces)
        let piece = |a: &AspectEntry, b: &AspectEntry| a.tid == b.tid && a.ak == b.ak;
        let same_but_hash = |a: &AspectEntry, b: &AspectEntry| (a.lo, a.hi, a.purge_by, &a.keys, a.replaces, a.original_floor) == (b.lo, b.hi, b.purge_by, &b.keys, b.replaces, b.original_floor);
        ord(
            self.aspects.is_sorted_by(|a, b| match piece(a, b) {
                true => a.ak.as_str() == PIECED && same_but_hash(a, b) && a.hash < b.hash,
                false => aspect_order(&a.tid, a.ak.as_str()) < aspect_order(&b.tid, b.ak.as_str()),
            }),
            "aspects not sorted and distinct",
        )?;
        ord(strictly_ascending(&self.purge, purge_bytes), "purge not sorted and distinct")?;
        ord(strictly_ascending(&self.keys, |k| *k), "delete keys not sorted and distinct")?;
        // a linked list's blobs commit to no delete key (spec/wire.md §5): its links name none
        // (`Header::resolve` holds every link of a list tree to its root's Del)
        for f in ListField::ALL {
            if let Some(l) = self.links.get(f) {
                ord(l.del == osis_base::Del::NONE, "header list link naming a delete key")?;
            }
        }
        // one path in the clear for every thing, or the split form: an entry per thing written,
        // two or more, never on a role commit (spec/wire.md §4 field 2)
        match &self.path {
            Paths::One(p) => {
                if !self.path_allowed(p) {
                    return Err(Error::Invalid("a path this commit may not state"));
                }
            }
            Paths::Split(s) => {
                ord(s.entries.len() == self.things().len(), "split path entries other than one per thing written")?;
                if self.kind.is_role() {
                    return Err(Error::Invalid("a role commit stating the split path form"));
                }
            }
        }

        let kind = self.kind;
        // session form belongs to content commits: role writes are commit form, so no later commit
        // can void them, and a snapshot has no own writes (spec/commits.md §3)
        if matches!(self.form, Form::Session(_)) && kind != Kind::Content {
            return Err(Error::Invalid("session form outside a content commit"));
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
            // the role timeline walks every grant write (spec/commits.md §2)
            if kind == Kind::RoleSnapshot && osis_schema::core_types::never_compacted(ak) {
                return Err(Error::Invalid("compaction snapshot of roles.0"));
            }
            if let Some(f) = fixed_purge_by(ak) {
                ord(a.purge_by == f, "purge-by of a fixed-retention aspect")?;
            } else if kind == Kind::ContentSnapshot && a.purge_by != PurgeBy::Writer {
                return Err(Error::Invalid("compaction-snapshot delta not purgeable by writer"));
            } else if ak == CREATED && a.purge_by != PurgeBy::Admin {
                // only an admin destroys a thing (spec/commits.md §5 Destruction)
                return Err(Error::Invalid("created.0 not purgeable by admin"));
            }
            // levels as listed (ascending, since keys sort by level first): exactly those the
            // purge-by calls for
            if levels != delete_levels(&a.purge_by) {
                return Err(Error::Invalid("delete levels do not match the purge-by"));
            }
        }
        // expiry: one per commit, on deltas that may expire (spec/commits.md §6)
        if let Some(t) = self.expires {
            ord(t <= FOREVER, "integer above 2^63 - 1")?;
            if kind.is_role() {
                return Err(Error::Invalid("expires on a role commit"));
            }
            if self.aspects.iter().any(|a| fixed_purge_by(a.ak.as_str()).is_some()) {
                return Err(Error::Invalid("expires on a commit with a fixed-retention aspect"));
            }
            if t <= wall {
                return Err(Error::Invalid("expires not after the commit's ts"));
            }
        }
        // one purge author per commit (spec/permissions.md §6), so at most one level-2 key: its
        // (spec/wire.md §4 field 11)
        if self.keys.iter().filter(|k| k.level == DELETE_AUTHOR).count() > 1 {
            return Err(Error::Invalid("more than one level-2 delete key"));
        }
        if used.iter().any(|u| !u) {
            return Err(Error::Malformed("delete key no aspect calls for"));
        }
        if !self.purge.is_empty() {
            if kind.is_role() {
                return Err(Error::Invalid("purge request on a role commit"));
            }
            if self.purge.iter().any(|p| is_role_class(p.ak().as_str())) {
                return Err(Error::Invalid("purge request naming role-class deltas"));
            }
            // a thing is destroyed or not: only a whole-aspect item names its mintings (spec/commits.md §5 Destruction)
            if self.purge.iter().any(|p| p.ak().as_str() == CREATED && !matches!(p, PurgeItem::Aspect { .. })) {
                return Err(Error::Invalid("purge item on created.0 by commit or by author"));
            }
            if self.purge.iter().filter(|p| matches!(p, PurgeItem::Author { .. })).count() > osis_base::format::MAX_AUTHOR_ITEMS {
                return Err(Error::Invalid("too many purge items by author"));
            }
        }
        if self.frontier.is_some() && kind != Kind::Role {
            return Err(Error::Invalid("frontier outside a role commit"));
        }
        // the adminless mark is a role commit's (spec/wire.md §4 field 14)
        if self.adminless && kind != Kind::Role {
            return Err(Error::Invalid("adminless mark not on a role commit"));
        }
        // an own cover is a durable content snapshot (spec/wire.md §4 field 14)
        if self.own_cover && (kind != Kind::ContentSnapshot || self.ephemeral.is_some()) {
            return Err(Error::Invalid("own cover not a durable content snapshot"));
        }
        // an ephemeral commit is a content commit or a content snapshot (each in its form, as a
        // durable one) and carries nothing a stored commit is for (spec/commits.md §2, §3)
        if let Some(c) = self.ephemeral {
            if !matches!(kind, Kind::Content | Kind::ContentSnapshot) {
                return Err(Error::Invalid("ephemeral commit neither a content commit nor a content snapshot"));
            }
            if !self.purge.is_empty() || self.links != Links::default() {
                return Err(Error::Invalid("ephemeral commit with a purge or linked lists"));
            }
            if self.aspects.iter().any(|a| a.purge_by != EPHEMERAL_PURGE_BY) {
                return Err(Error::Invalid("ephemeral commit with a purge-by other than writer"));
            }
            // relay-only: snapshot deltas of signals, never stored, so nothing to expire or undo
            if c == EphClass::Relay && (kind != Kind::ContentSnapshot || self.expires.is_some() || self.undoes.is_some()) {
                return Err(Error::Invalid("relay-only commit not a content snapshot, or with an expiry or an undo"));
            }
        }
        Ok(())
    }

    /// Whether it may state `p` for a thing it writes.
    pub fn path_allowed(&self, p: &Path) -> bool {
        // Interim (issues/stated-path-certificates.md): a role commit's index names its signer, until its purge
        // author is indexed along stated paths
        self.kind != Kind::Role || p.purge == 0
    }
}
