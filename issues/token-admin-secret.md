# A writer that is not an admin cannot derive the level-1 delete token
> Summary: spec/crypto.md §7 gives every `admin`/`author`/`writer` delta a level-1 token from the thing's admin secret, but a write-role member does not hold that secret, so it cannot compute the token hash the header must list; osis-commit omits level 1 in that case (provisional). Owner accepted option 1 for the MVP; revisit post-MVP.
> Tags: commit, crypto, post-mvp

Repro: design: `osis_commit::token_secrets` (provisional) omits level 1 for a non-admin writer.

## Problem
Token hash = BLAKE3(kdf("delete token", secret, salt))[..16] needs the secret itself. A member with write on a thing (a group thing shared to writers, or a thing it does not own) holds the thing's read and write secrets, not its admin secret (spec/crypto.md §3, §4). So the default `author` retention (levels 1 and 2) cannot be written as specified by a non-admin writer.

## Options
1. **Omit level 1 when the writer lacks the admin secret** (implemented in `osis_commit::token_secrets`, marked provisional; membership deltas too since membership-flows: invite grants, self-removals and writers' rotations and re-seals are written by non-admins, and their only token is level 1, so such a body is deleted at blind nodes by the delete key only). Cost: a thing admin who is not an admin of the label's group cannot delete that writer's bodies at blind nodes by token; honest nodes still drop them on purge request, and label admins still delete by the delete key. Header validation accepts a subset of the levels the retention calls for.
2. A per-thing token secret readable by writers (e.g. `kdf("admin token", write secret)`) for level 1: then every writer can delete every `admin` body at blind nodes, which defeats `admin`.
3. Let the admin-level token derive from a public value plus the admin secret (an asymmetric commitment), so a writer can commit without holding the secret: new primitive, more bytes per blob.

Recommended: 1 for the MVP (simple, no new crypto; the gap is a deletion convenience at untrusted servers, not a confidentiality or integrity property).
