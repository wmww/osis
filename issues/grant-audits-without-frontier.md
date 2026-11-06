# A grant that audits carries no frontier
> Summary: `Engine::grant` writes no frontier, but spec/permissions.md §5.1 step 4 makes some grants audit, with an empty frontier undoing the holder's earlier writes everywhere. The API refuses the role case; a lower `may_grant` (the spec's invite) still undoes the grants the holder made by it, and no call lowers it without that. Also a grant made by `may_grant` over an ended grant conflicts with §2's wording.
> Tags: security, engine, api

An explicit write audits when the edge as restored exceeds its new value (spec/permissions.md §5.1 step 4, audits). `grant_in` never calls `m.frontier`; `remove_signed` is the only path computing one.

- **Role below one lost** (self-removal or an `until`, finalized or not), fixed at the API: `grant` is `Invalid`, `set_role` removes first (`below_lost` in `core/osis/src/share.rs`, `Engine::lost_role`). Without it, re-adding at a lower role someone who had left would undo all they ever wrote. `grant_as` and other engine callers are not covered.
- **Lower `may_grant`, open.** `grant(g, b, Read, default)` over `may_grant: Some(Read)` removes at once, at the granter, the grant `b` made by it to carol (carol's own node still says she holds it). Reproduce: alice grants bob Read with `may_grant` Read, bob grants carol, alice grants bob Read with no `may_grant`, `alice.grants(g)` lacks carol. `set_role` caps `may_grant` through `lower`, with a frontier, but cannot lower it alone.
- **`until` on a live grant**: the rule's wording says it audits too; probes of content and of an admin's grants saw nothing undone. Check what the walk does and fix one of the two.
- **Invite grant over an ended grant** (made by `may_grant`): §2 says an expired grant counts as none, but with the grant still in the state and above the new role, validity refuses the commit ("a removal without the rotation it requires") and a holder granting by `may_grant` cannot rotate. The flow answers `Permission`. Either §2 says so or validity exempts it.

Proposal: `grant_in` carries a frontier whenever its write audits, as `remove_signed` computes it, and a grant lowering `may_grant` takes the same pre-sync through `set_role`-like options. Then the API's refusal may stay only for the pre-sync's sake. Touches engine flows: after owner removal.
