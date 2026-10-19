//! Structural validation of a resolved header (spec/wire.md §4, spec/commits.md §2, §5, §6).

use crate::cbor::strictly_ascending;
use crate::header::{FOREVER, Header, Kind, aspect_key, purge_value, token_value};
use crate::retention::{CREATED, check_retention, fixed_retention, token_levels};
use crate::Error;
use osis_core::format::FORMAT_VERSION;
use osis_schema::PurgeBy;
use osis_schema::core_types::is_membership_class;

const ROSTER_AKS: [&str; 2] = ["/members", "/tenures"];

impl Header {
    /// Checks every layout rule and every rule of spec/commits.md §2 a header shows: sort orders,
    /// indices, ranges, kinds and aspect classes, fixed retention, expiry, purge, frontier,
    /// origins, token levels. Linked lists must be resolved first.
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
        ord(strictly_ascending(&self.purge, |p| osis_core::encode(&purge_value(p))), "purge not sorted and distinct")?;
        ord(strictly_ascending(&self.tokens, |t| osis_core::encode(&token_value(t))), "tokens not sorted and distinct")?;
        ord(strictly_ascending(&self.origins, |o| o.commit), "origins not sorted and distinct")?;

        let kind = self.kind;
        let wall = self.ts.wall_ms().0;
        let mut used = vec![false; self.tokens.len()];
        for a in &self.aspects {
            let ak = a.ak.as_str();
            // indices and ranges
            ord(!a.hashes.is_empty(), "aspect without delta hashes")?;
            let nums = [Some(a.lo), Some(a.hi), a.expires, a.retention.at_least.abs, a.retention.at_least.rel, a.retention.at_most.abs, a.retention.at_most.rel];
            ord(nums.iter().flatten().all(|n| *n <= FOREVER), "integer above 2^63 - 1")?;
            if a.schema.is_some_and(|i| i >= self.schemas.len()) {
                return Err(Error::Malformed("schema index out of range"));
            }
            ord(strictly_ascending(&a.tokens, |i| *i), "aspect tokens not ascending")?;
            let mut levels = Vec::with_capacity(a.tokens.len());
            for i in &a.tokens {
                let tok = self.tokens.get(*i).ok_or(Error::Malformed("token index out of range"))?;
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
            // levels as listed (ascending, since tokens sort by level first): exactly those the
            // retention calls for; only level 1 may be missing, and not on membership commits
            // (provisional, issues/token-admin-secret.md)
            let required = token_levels(&a.retention, kind);
            let without_admin: Vec<u8> = required.iter().copied().filter(|l| *l != 1).collect();
            if levels != required && (kind.is_membership() || levels != without_admin) {
                return Err(Error::Invalid("token levels do not match the retention"));
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
        if used.iter().any(|u| !u) {
            return Err(Error::Malformed("token no aspect calls for"));
        }
        for c in &self.chunks {
            ord(strictly_ascending(&c.tokens, |t| t.0), "chunk tokens not ascending")?;
            if c.tokens.iter().any(|t| t.0 >= self.tokens.len()) {
                return Err(Error::Malformed("chunk token index out of range"));
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
