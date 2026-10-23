//! What a demotion's frontier must cover (spec/permissions.md §5.1, "Frontier"): for each node
//! the change demotes, the things whose membership-class aspects it puts in question (any
//! fall) and the things whose every aspect it puts in question (a fall below write). The node
//! fills the counters from its receipt record (§5.1: what it had received as of T).

use crate::graph::View;
use crate::timeline::Timeline;
use crate::types::Edge;
use osis_core::{Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};

/// The aspects a demotion puts in question, per demoted node.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DemotionScope {
    /// Node -> things whose membership-class aspects need its counters.
    pub membership: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Node -> things whose every aspect needs its counters.
    pub content: BTreeMap<Tid, BTreeSet<Tid>>,
}

impl DemotionScope {
    pub fn is_empty(&self) -> bool {
        self.membership.is_empty() && self.content.is_empty()
    }
}

impl Timeline {
    /// The scope of setting `member`'s edge on `target` to `new` now (at `ts`, after every
    /// held write), as if the member still held what it had: empty when it demotes nobody.
    /// `author` (the demoter) is never its own subject.
    pub fn demotion_scope(&self, author: &Tid, member: &Tid, target: &Tid, new: Option<Edge>, ts: Ts) -> DemotionScope {
        let mut out = DemotionScope::default();
        let now = self.edges_at(None);
        let was = now.get(member, target).map(|e| Edge { until: None, since: None, ..*e });
        let before_v = View::at(&self.owners, &now, Some(ts)).patched(*member, *target, was);
        let after_v = View::at(&self.owners, &now, Some(ts)).patched(*member, *target, new);
        let ns = before_v.reach_forward(target);
        for x in before_v.reach_backward(member) {
            // Only nodes write; an actor's nodes are reached through it.
            if x == *author || self.owners.owner_actor(&x).is_some() {
                continue;
            }
            let (b, a) = (before_v.roles_from(&x), after_v.roles_from(&x));
            for n in &ns {
                let (sb, sa) = (before_v.standing(&x, &b, n), after_v.standing(&x, &a, n));
                if sa.class < sb.class || sa.role < sb.role {
                    out.membership.entry(x).or_default().insert(*n);
                }
                if sb.role >= Some(Role::Write) && sa.role < Some(Role::Write) {
                    out.content.entry(x).or_default().insert(*n);
                }
            }
        }
        out
    }
}
