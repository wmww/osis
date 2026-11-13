# A forgotten `secrets.0` part rejoins late and gives back the lost secrets
> Summary: After a node loses read access to actor X, the forgotten `secrets.0` part of X's old grant to a group G the node still reads comes back as a late part (its copy blob is under G's kept label), and at the next open its box to G yields X's old read secrets again; nothing judges X lost again, so the node reads X's content once more (spec/permissions.md §3 Lost access: drop those role secrets).
> Priority: critical
> Tags: security, engine, node-sync

Repro (node `it`): the stored twin of `ephemeral::partly_forgotten_durable_commit_keeps_no_key_of_the_lost_part_spec_permissions_3` (a grants x read to g, r reads g; one commit writes w1 of g and w2 of x; a demotes g on x), then `net.restart(r, ..)` and a few `advance(31_000)`: r holds 2 read secrets of x, `may_read(r, w2)` is false, and `read(r, w2)` gives the old value. Same on main before forget-parts.

- Order seen: right after the loss the grant commit's `secrets.0` part on x is `Hold::Missing` (forgotten parts are not marked, so they "join late if they come back"); within a few passes (no restart needed) it is held again from its copy under g's label; the next open (`read_pending_boxes`/keys at start) takes x's secrets from its box to g; `reopen_undropped(None)` at start then refetches the content blob and w2's section opens.
- Nothing re-runs the lost check: the `l/` trigger lists `roles.0` targets of received role commits, not a late `secrets.0` part.
- Fix direction (design call for the fixer): a forgotten part on a thing still lost must not rejoin (mark it as `Missing::Forgot` marks a released thing's parts, cleared when the node reads the thing again, which then refetches), or key extraction keeps no secret of an actor `lost::readable` says the node cannot read. Re-judging after the join instead would loop (forget, relist, rejoin) every pass.
