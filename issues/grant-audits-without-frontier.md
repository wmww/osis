# A grant that audits carries no frontier
> Summary: `Engine::grant` writes no frontier, but spec/permissions.md §5.1 step 4 makes some grants audit, with an empty frontier undoing the holder's earlier writes everywhere. The API refuses the role case; a lower `invite` still undoes the holder's invite grants, and no call lowers an invite without that. Also an invite grant over an ended edge conflicts with §2's wording.
> Tags: security, engine, api

An explicit write audits when the edge as restored exceeds its new value (spec/permissions.md, Tenure ledger paragraph). `grant_in` never calls `m.frontier`; `remove_signed` is the only path computing one.

- **Role below one lost** (self-removal or an `until`, finalized or not), fixed at the API: `grant` is `Invalid`, `set_role` removes first (`below_lost` in `core/osis/src/share.rs`, `Engine::lost_role`). Before that, re-adding at a lower role someone who had left undid all they ever wrote. `grant_as` and other engine callers are not covered.
- **Lower `invite`, open.** `grant(g, b, Read, default)` over `invite: Read` removes at once, at the granter, the grant `b` made by invite to carol (carol's own node still says she holds it). Reproduce: alice grants bob Read with invite Read, bob grants carol, alice grants bob Read with no invite, `alice.grants(g)` lacks carol. `set_role` caps the invite through `lower`, with a frontier, but cannot lower it alone.
- **`until` on a live edge**: the rule's wording says it audits too; probes of content and of an admin's grants saw nothing undone. Check what the walk does and fix one of the two.
- **Invite grant over an ended edge**: §2 says an expired edge counts as none, but with the edge still in the state and above the new role, validity refuses the commit ("a removal without the rotation it requires") and an invite holder cannot rotate. The flow answers `Permission`. Either §2 says so or validity exempts it.

Proposal: `grant_in` carries a frontier whenever its write audits, as `remove_signed` computes it, and a grant lowering `invite` takes the same pre-sync through `set_role`-like options. Then the API's refusal may stay only for the pre-sync's sake. Touches engine flows: after owner removal.
