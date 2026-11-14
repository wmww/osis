# A retainer the node cannot read counts as known
> Summary: `lifetimes::status` (core/engine/src/retention/lifetimes.rs:53) calls a thing known when a live minting is held, with no reading test, while notes/lifetimes.md says known means "held and may read it" and an unread retainer keeps. An unread retainer has no reference rows, so a thing listing only it walks as unreachable and a node with the purge right releases it: destroyed at every node. Lost access keeps `created.0` (`forget.rs:33`), so a member removed from folder F releases its own things that list F as retainer.
> Priority: critical
> Tags: engine, lifetimes

Found by reading (notes/cannot-read-audit.md), no reproducer yet. Path: `forget` keeps F's `created.0`, `copy_of(F)` is None (erased, not kept), so `status(F)` = Known; `refs::references(F, D)` is false (F's rows cleared); `walk` finds no unknown or standalone retainer; `may_end(D)` holds for D's admin; `release` writes the request. Also reached by any thing whose `created.0` arrives as a certificate or chain part (cards, a keeper's grant chain).

Fix shape: known needs a held path that reads the thing (`forget::read_path` or `rotation::readable`), as the note states; `forget`'s `queue_with_listers` then really makes listers re-judge it as unknown. First a small osis test: remove the member, check D lives at the other members.
