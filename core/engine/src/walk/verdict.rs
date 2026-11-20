//! A part's verdict as the engine gives it once the walk along stated paths decides: the walk's
//! (`Paths::status`, `Paths::content`), and for the deltas the walk does not judge, the engine's
//! own rule beside it (notes/perm-paths.md, The switch: who judges what the walk does not).

use crate::engine::Core;
use crate::walk::input::{Input, Origin};
use osis_perm::paths::{Content, PartKind, Paths, Status, Store};
use osis_perm::WriteId;

/// Whether delta part `ix` of `input` is valid: never where its commit is void (overlapping
/// session ranges, `Indexes::void`: spec/commits.md §4); by the walk, else
/// - an external fire (spec/permissions.md §5.2 External fires): iff its thing's current setting
///   enables its signal;
/// - an invite grant's boxes (notes/a1-spec/permissions.md §2 Invite grant: "it carries the
///   grantee's boxes for those roles"): a `secrets.0` or `keys.0` part writing only its grantees'
///   boxes (`Indexes::grant_overreach`, judged from the delta alone) where every grant its commit
///   puts on the thing applies as an invite grant.
pub fn delta_valid<S: Store>(core: &Core, paths: &Paths<S>, input: &Input, ix: usize) -> bool {
    let c = &input.commit;
    if core.ix.void.contains(&c.id) {
        return false;
    }
    if matches!(paths.content(&WriteId(c.id, u32::try_from(ix).unwrap_or(u32::MAX))), Some(Content::Valid(_))) {
        return true;
    }
    let (Some(part), Some(Origin::Delta(ai))) = (c.parts.get(ix), input.origins.get(ix)) else { return false };
    let PartKind::Delta(d) = &part.kind else { return false };
    if d.aspect.external() {
        return crate::apply::validity::setting_now(core, &part.on).is_some_and(|s| s.enables(&d.aspect));
    }
    if matches!(d.aspect.as_str(), "secrets.0" | "keys.0") && !core.ix.grant_overreach.contains(&(c.id, *ai)) {
        let mut puts = (0u32..).zip(&c.parts).filter(|(_, p)| p.on == part.on && matches!(&p.kind, PartKind::Edge(e) if e.value.is_some())).peekable();
        return puts.peek().is_some() && puts.all(|(i, _)| paths.status(&WriteId(c.id, i)) == Some(Status::Invited));
    }
    false
}
