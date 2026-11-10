# A fallen ending request costs a from-scratch walk per role pass
> Summary: `purge::holds_right` judges a request on `created.0` with a timeline walked from scratch over the whole held role graph whenever an edge write on the thing stamped after the request is held. Once the thing ended those are dropped, but while the request does not stand (it fell, or never held the right) the thing stays live, later edge writes accumulate, and every `rejudge_purges` of the thing (each role change on it or above it) walks the node's whole role graph again, per minting the request names.
> Priority: normal
> Tags: engine, permissions, security

- Read, not run. Who can cause it: a signer that could ever hold the right (`signers_could` filters the rest), e.g. an admin whose ending a demotion upstream undid; it then lasts for the thing's life at every node.
- Scales with the node's role graph, not with the thing (notes/coordination.md, Fast by construction).
- Directions: (a) perm answers "does the right stand at P without edge writes on t after P" from the incremental timeline (only audits and the final-state re-grant read later writes on t); (b) the verdict of a request that held no right while its later writes are held is cached per request until an edge write at or before P on its path changes.
