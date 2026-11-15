# The reference graph: one plan for sync, holding, lifetime, invitations and storage
> Summary: Tess's design, decided with her. The plan, its demolition inventory, the rewritten spec, the model and the requirements wording for her sign-off are on the GitHub branch `sextant-reference-graph` (start at its `issues/reference-graph.md`); they are not on main because the spec there describes what is not built yet. To execute after the account forks work: rebase that branch once, then demolition and rebuild on main as its Execution section says.
> Priority: normal
> Tags: engine, sync, data-model, permissions

In short (the branch has the rules):
- Every reference is a strong, a weak or a ticket; no value is a bare tid, and nothing has a default strength.
- A strong says "this belongs here" and grants nothing. A node holds what its node root reaches by strongs, entering a thing with its own keys only by a ticket it can open. A thing is deleted when its last reference goes; no rule waits on an absent peer.
- What a sync ID carries stays today's rule: what its own keys can open.
- A ticket is a weak that carries what is needed to sync its target; accepting is writing a strong. Invitations are tickets fired on an account's inbox thing, on a signal marked `@` that anyone holding the account's public record may fire.
- Gone: retainers, release requests, synced groups, default filing, the group concept (`holds.0` and tags stay), inbox blobs, grant copies, the acted-on set, the account's sync records, tied grants, the `delete` call, the sync-exempt aspects.
- Execution: main may be broken; spec first, baselines by the executing coordinator, one demolition (tests included), a foundation commit, three rebuild lanes at once, new tests last, one gate. Fewer and faster tests at the end is a condition.

Related on main: issues/storage-follows-groups.md (audit input), issues/links-as-tickets.md, issues/one-open-proof.md, issues/text-links-as-references.md, issues/refs-in-chunked-elements.md.
