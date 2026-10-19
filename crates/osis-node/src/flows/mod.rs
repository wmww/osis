//! Membership flows (plans/membership-flows.md): person actors, pairing, grants, demotions with
//! pre-sync and the receipt-record frontier (`Engine::frontier`), rotation cascade, re-seal,
//! roster snapshots, links, cards, moving things. Builds membership commits with `Mutation`
//! (`frontier`; `Mutation::unchecked` where perm's rules for invite grants and self-removals
//! decide authority instead of the plain role check).
