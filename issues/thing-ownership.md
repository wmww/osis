# Thing lifetimes by ownership
> Summary: Proposal agreed in outline with Tess, needs a design study before building: a thing may name its owners (`owner.0`, a set); it lives while some owner still holds a reference to it and is itself alive, up to a root (a thing with no owner); anything not reachable that way is dropped, cycles included. Replaces "every program works out when to delete its things" for structured data. API contract first; implementation later.
> Priority: normal
> Tags: tess-call, data-model, api, permissions, sync

## Contract (agreed with Tess)
- Three lifetimes: **root** (no owner; deleted explicitly, as today), **owned** (below), **expiring** (expiry, `osis::KeepAlive`; unchanged).
- `owner.0` on the thing: the set of things that own it. Mutable (move, adopt, detach are rewrites of it); admin-only on the thing.
- An owner holds the thing by an ordinary reference in its own data. A thing is **alive** while, walking up its owners, some path reaches a root through owners that are alive and still hold it. Anything else is dropped: released by its last owner, every owner gone, or a cycle no root reaches.
- Cycles are not prevented or broken: a thing in a cycle no root reaches is dropped like any other unreachable thing. Tess: cycles are an edge case; dropping is the expected contract. Two concurrent moves that close a cycle drop it too (accepted).
- Plain references stay weak: one to a dropped thing reads as gone, never an error.
- Dropping is final.

## For the study
- Who writes the delete: a node that does not hold the owned thing cannot write its delete; the delete is a duty of any node holding the thing and enough of its ancestry to judge it unreachable, with a delete right given to owners' writers over things that name them. A node missing part of the ancestry does not delete (leaks rather than wrongly deletes).
- Whether owned things must be readable wherever their owners are (one sharing context) or the leak at nodes outside is a stated limit.
- Deterministic judgment: what is judged from held data, what is an action (the delete) that may depend on timing.
- Cost of the upward walk (deep or wide ancestry), caching it; growth (notes/growth.md).
- Interaction with retention (issues/thing-history.md), expiry, removal of members, forks and disputes.
- API shape (notes/api-design.md): create owned, move, release, adopt, detach.
