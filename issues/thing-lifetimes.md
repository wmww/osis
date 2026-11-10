# Thing lifetimes by reference
> Summary: Proposal agreed in outline with Tess, needs a design study before building: a thing may name the things whose references keep it alive (`refd_by.0`, a set); it lives while one of them is alive and still references it, up to a standalone thing (one with no `refd_by.0`); anything not reachable that way is dropped, cycles included. No strong-reference type: a reference counts iff it comes from a listed thing. Shares its index with backlinks. API contract first; implementation later.
> Priority: normal
> Tags: tess-call, data-model, api, permissions, sync

## Contract (agreed with Tess)
- Three lifetimes: **standalone** (no `refd_by.0`; deleted explicitly, as today), **referenced** (below), **expiring** (expiry, `osis::KeepAlive`; unchanged).
- `refd_by.0` on the thing: the set of things whose references keep it alive. Mutable (adding, moving and making standalone are rewrites of it); admin-only on the thing.
- A listed thing keeps it alive by an ordinary `tid` reference anywhere in its own data (a tid is self-describing on the wire, CBOR tag 1616, so no schema is needed to find it). A reference counts iff it comes from a thing listed in `refd_by.0`; every other reference is weak. There is no strong-reference type: one source of truth.
- A thing is **alive** while, walking up `refd_by.0`, some path reaches a standalone thing through things that are alive and still reference the one below. Anything else is dropped: its last listed referrer stopped referencing it, every listed referrer is gone, or a cycle no standalone thing reaches.
- Cycles are not prevented or broken: a cycle no standalone thing reaches is dropped like anything unreachable. Tess: cycles are an edge case; dropping is the expected contract. Two concurrent rewrites that close a cycle drop it too (accepted).
- Weak references to a dropped thing read as gone, never an error.
- Dropping is final.
- Naming: "owner"/"ownership" must not be used (a concept being removed elsewhere).

## Backlinks (Tess)
A user feature that will be needed: opening a note shows every note that links to it. Efficient backlinks need a node-local reverse index of `tid` references in held data (which held things reference X), the same index reference tracking needs to answer "does referrer R still reference X" and to react when that changes. Design the index once, for both: what it covers (held things only; a node cannot see references it does not hold), its cost per write (O(references changed)), and its growth (notes/growth.md).

## For the study
- Who writes the delete: a node that does not hold the referenced thing cannot write its delete; the delete is a duty of any node holding the thing and enough of its referrers to judge it unreachable, with a delete right given to writers of a listed referrer over things that list it. A node missing part of the chain does not delete (leaks rather than wrongly deletes).
- Whether referenced things must be readable wherever their referrers are (one sharing context) or the leak at nodes outside is a stated limit.
- Deterministic judgment: what is judged from held data, what is an action (the delete) that may depend on timing.
- Cost of the upward walk (deep or wide chains), caching it; growth.
- Interaction with retention (issues/thing-history.md), expiry and ending (retention/end.rs, Fathom's), removal of members, forks and disputes.
- API shape (notes/api-design.md): create referenced, add or move referrers, make standalone; backlink queries.
