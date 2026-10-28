//! Structural validation of a resolved header (spec/wire.md §4, spec/commits.md §2, §5, §6).

use crate::cbor::strictly_ascending;
use crate::header::{FOREVER, Header, Kind, aspect_key, key_value, purge_value};
use crate::retention::{CREATED, check_retention, delete_levels, fixed_retention};
use crate::Error;
use osis_base::format::FORMAT_VERSION;
use osis_schema::PurgeBy;
use osis_schema::core_types::is_membership_class;

const ROSTER_AKS: [&str; 2] = ["/members", "/tenures"];

impl Header {
    /// Checks every layout rule and every rule of spec/commits.md §2 a header shows: sort orders,
    /// indices, ranges, kinds and aspect classes, fixed retention, expiry, purge, frontier,
    /// origins, delete levels. Linked lists must be resolved first.
    pub fn validate(&self) -> Result<(), Error> {
        if !self.is_resolved() {
            return Err(Error::Missing);
        }
        if self.version != FORMAT_VERSION {
            return Err(Error::Malformed("format version"));
        }
        let ord = |ok: bool, what: &'static str| if ok { Ok(()) } else { Err(Error::Malformed(what)) };
        ord(strictly_ascending(&self.schemas, |s| s.0), "schemas not sorted and distinct")?;
        ord(self.schemas.iter().all(|s| s.1 <= FOREVER), "integer above 2^63 - 1")?;
        ord(!self.aspects.is_empty(), "no aspects")?;
        ord(strictly_ascending(&self.aspects, |a| aspect_key(&a.tid, &a.ak)), "aspects not sorted and distinct")?;
        ord(strictly_ascending(&self.chunks, |c| c.blob), "chunks not sorted and distinct")?;
        ord(strictly_ascending(&self.purge, |p| osis_base::encode(&purge_value(p))), "purge not sorted and distinct")?;
        ord(strictly_ascending(&self.keys, |t| osis_base::encode(&key_value(t))), "delete keys not sorted and distinct")?;
        ord(strictly_ascending(&self.origins, |o| o.commit), "origins not sorted and distinct")?;

        let kind = self.kind;
        // membership writes are commit form, so no later commit can void them (spec/commits.md §3)
        if matches!(kind, Kind::Membership | Kind::RosterSnapshot) && self.form == crate::header::Form::Node {
            return Err(Error::Invalid("node-form membership commit"));
        }
        let wall = self.ts.wall_ms().0;
        let mut used = vec![false; self.keys.len()];
        for a in &self.aspects {
            let ak = a.ak.as_str();
            // indices and ranges
            ord(!a.hashes.is_empty(), "aspect without delta hashes")?;
            let nums = [Some(a.lo), Some(a.hi), a.expires, a.retention.at_least.abs, a.retention.at_least.rel, a.retention.at_most.abs, a.retention.at_most.rel];
            ord(nums.iter().flatten().all(|n| *n <= FOREVER), "integer above 2^63 - 1")?;
            if a.schema.is_some_and(|i| i >= self.schemas.len()) {
                return Err(Error::Malformed("schema index out of range"));
            }
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
            if kind.several_deltas() {
                ord(strictly_ascending(&a.hashes, |h| *h), "delta hashes not sorted and distinct")?;
            } else if a.hashes.len() != 1 {
                return Err(Error::Invalid("more than one delta on an aspect of this kind"));
            }
            // kinds and aspect classes
            if ak != CREATED && is_membership_class(ak) != kind.is_membership() {
                return Err(Error::Invalid("aspect of the wrong class for the commit kind"));
            }
            match kind {
                Kind::RosterSnapshot if !ROSTER_AKS.contains(&ak) => return Err(Error::Invalid("roster snapshot of a non-roster aspect")),
                Kind::MembershipSnapshot if ROSTER_AKS.contains(&ak) => return Err(Error::Invalid("compaction snapshot of /members or /tenures")),
                _ => {}
            }
            // retention
            check_retention(&a.retention)?;
            if let Some(f) = fixed_retention(ak) {
                ord(a.retention == f, "retention of a fixed-retention aspect")?;
            } else if kind == Kind::ContentSnapshot && a.retention.by != PurgeBy::Writer {
                return Err(Error::Invalid("compaction-snapshot delta not purgeable by writer"));
            }
            // levels as listed (ascending, since keys sort by level first): exactly those the
            // retention calls for
            if levels != delete_levels(&a.retention, kind) {
                return Err(Error::Invalid("delete levels do not match the retention"));
            }
            // expiry
            if let Some(t) = a.expires {
                if fixed_retention(ak).is_some() {
                    return Err(Error::Invalid("expires on a fixed-retention aspect"));
                }
                if kind.is_membership() {
                    return Err(Error::Invalid("expires on a membership commit"));
                }
                if !self.purge.is_empty() {
                    return Err(Error::Invalid("expires on a commit with a purge request"));
                }
                if t <= wall {
                    return Err(Error::Invalid("expires not after the commit's ts"));
                }
            }
        }
        if kind == Kind::RosterSnapshot && self.aspects.windows(2).any(|w| matches!(w, [x, y] if x.tid != y.tid)) {
            return Err(Error::Invalid("roster snapshot of several things"));
        }
        // one author chain: at most one level-2 key (header-list blobs commit to it alone)
        if self.keys.iter().filter(|k| k.level == 2).count() > 1 {
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
            if kind.is_membership() {
                return Err(Error::Invalid("purge request on a membership commit"));
            }
            if self.purge.iter().any(|p| is_membership_class(p.ak().as_str())) {
                return Err(Error::Invalid("purge request naming membership deltas"));
            }
        }
        if self.frontier.is_some() && kind != Kind::Membership {
            return Err(Error::Invalid("frontier outside a membership commit"));
        }
        if self.origins.is_empty() == (kind == Kind::Import) {
            return Err(Error::Invalid("origins present iff import"));
        }
        Ok(())
    }
}
