# A thing's admin cannot wipe a write-only member's data from servers by token
> Summary: When a member with write (not admin) rights on a thing writes to it, the thing's admin can still purge that data from every honest device and the sharing group's admins can delete it at servers, but the thing's admin alone cannot delete those server copies by token. Fixing it needs a new deletion primitive (about 16 more bytes per stored blob and a signature check per deletion). Owner accepted the gap for the MVP.
> Tags: commit, crypto, post-mvp

## The decision (user terms)
Deleting data from an untrusted server is done by presenting a token the server can check. For data written by a member who may write but not administer the thing:
- **Keep the gap** (accepted for MVP): honest devices drop the data on a purge; the group's admins can wipe the server copies; the thing's own admin cannot do so by token. No confidentiality or integrity property is involved, only who can clean up servers.
- **Signature-based admin tokens**: the thing's admin can always wipe server copies. Costs a new primitive in the format: every stored blob carries a 32-byte admin verification key instead of a 16-byte token hash, and servers verify a signature per deletion.
- **A token every writer can derive**: closes the gap but lets any writer wipe admin-level data at servers, which defeats the point of admin-only deletion. Not recommended.

Recommended: keep the gap; revisit if server cleanup by thing admins turns out to matter in practice.

## Technical details
spec/crypto.md §7 gives every `admin`/`author`/`writer` delta a level-1 token from the thing's admin secret. Token hash = BLAKE3(kdf("delete token", secret, salt))[..16] needs the secret itself. A member with write on a thing holds the thing's read and write secrets, not its admin secret (spec/crypto.md §3, §4), so it cannot compute the level-1 token hash the header must list. `osis_commit::token_secrets` (provisional) omits level 1 in that case; header validation accepts a subset of the levels the retention calls for. Membership deltas written by non-admins (invite grants, self-removals, writers' rotations and re-seals) have only a level-1 token, so such bodies are deleted at blind nodes by the label delete key only. A per-thing token secret readable by writers (e.g. `kdf("admin token", write secret)`) would let every writer delete every `admin` body. An asymmetric commitment (an admin signing key whose public key is listed in the header, the token being a signature over the blob id) is the shape of the signature option; token vectors are provisional, so it is a spec edit, not a frozen-format change. Related: header-list chunks carry level-2 commitments only (notes/crypto.md).
