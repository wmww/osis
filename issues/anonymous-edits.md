# Anonymous (pseudonymous) edits
> Summary: Optional per-actor setting hiding real authors behind per-label pseudonyms from readers and optionally from writers; can be added later if a few design rules hold from the start. Discuss with owner before deciding.
> Tags: permissions, crdt-sync, sync, security

## Today
Every commit is signed by the author's node and every state element carries the author node's dot, so all readers see who wrote what. Readers need authorship to verify writes (author chains travel under labels) and to drop a revoked writer's edits.

## Proposal (agent, 2026-10-16, not discussed)
- Per-actor setting, chosen by its admins: who sees real authors (readers and up = today, writers and up, admins only, nobody).
- Commits carry a per-(node, label) pseudonym; the real author signature and chain are encrypted to the chosen level. Readers verify pseudonym certificates and role-key epochs instead of author chains; revokes name pseudonyms.
- "Admins only" keeps surgical removal: admins map pseudonyms to members. "Nobody" can only revoke a pseudonym; removing the person behind it means rotating everyone.
- Open: who certifies a pseudonym. Self-issued under the writer role key (offline, but escrow is self-reported and only checked when unmasked) vs admin-issued at grant time (trustworthy unmasking, a new device needs an admin online). Leaning admin-issued.
- Limits: edits under one pseudonym are linkable within a label; timing and style leak. Old history keeps real authors.
- History before access can be hidden by giving new readers snapshots instead of the log; per-element timestamps remain (coarsenable).

## Rules to keep it addable later
1. Dot author IDs are opaque fixed-size IDs; reader-side code never treats them as node tids or resolves them.
2. Author identity is one separable header field, so it can be encrypted.
3. Commit headers carry a signature-scheme enum.
4. Reader-side authorization and revocation go through one interface (author ID in, verdict out).
5. Author visibility is a per-actor setting; default = today's behavior.

Retrofit cost otherwise: a header format version, all nodes of a group upgrading before using it.
