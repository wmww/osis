# Verifiers need membership data up the owner chain
> Summary: Checking any write on a thing needs the current membership of its owner and of every actor above it up to the key actor, but only members hold those actors' read secrets. A grantee (Bob with an edge on N) or a chat reader cannot verify writes or learn of admin revocations, so nodes diverge. Found 2026-10-11 while resolving sharing.
> Tags: permissions, security, sync

Scenario: Alice's actor A owns note N; an admin device D of A writes "Bob: write" on N. Bob must check that D is an admin of A, which is A's membership aspect, encrypted for A's members. Same for every write by A's members to N, and for the chat pattern (readers verify a participant's writes but are not members of the participant's person actor). notes/data-model.md checks creation records by hash, which proves identity, not current membership.

Revocation makes it worse: if D is removed from A (stolen device), Bob never learns it, keeps accepting D's writes, and Alice's nodes reject them; the receipt-time rule needs the revoke and statements to reach every verifier.

Options:
- Membership aspects readable by everyone below: a "verify" role under read, whose key is handed out with every edge and membership, transitively up the chain. Simple; leaks each actor's member and device list (node tids, counts) to everyone it shares anything with.
- Certificate chains: membership edges are signed statements; a commit carries or references the chain from its author node to the owner's key actor. Verifiers learn only the chain used. Needs a revocation feed per actor that verifiers can subscribe to, and the chain adds a few hundred bytes per commit unless cached per (node, actor).
- Hybrid: chains for verification, membership aspect readable only by members, revocations published as signed statements under a label verifiers can sync.

Decide with the receipt-time rule in hand (notes/permissions.md). Blind nodes are unaffected: they verify nothing.
